package app.phishguard.companion

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Sends queued SMS to your server in batches; retries later (with backoff) if the server or the network is unavailable. */
class UploadWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val ctx = applicationContext
        if (!Prefs.isConfigured(ctx)) return@withContext Result.failure()
        while (true) {
            val batch = Outbox.peek(ctx, Protocol.MAX_BATCH)
            if (batch.isEmpty()) return@withContext Result.success()
            try {
                Api.post(ctx, "/api/ingest/sms/batch", Protocol.batchJson(batch))
            } catch (e: ApiException) {
                // 4xx (bad token, ingest disabled) will not fix themselves; 5xx and timeouts are worth another try.
                return@withContext if (e.status in 400..499) Result.failure() else Result.retry()
            } catch (e: Exception) {
                return@withContext Result.retry()
            }
            Outbox.drop(ctx, batch.size)
        }
        @Suppress("UNREACHABLE_CODE")
        Result.success()
    }

    companion object {
        fun enqueue(ctx: Context) {
            val req = OneTimeWorkRequestBuilder<UploadWorker>()
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(ctx.applicationContext).enqueueUniqueWork("pg-upload", ExistingWorkPolicy.APPEND_OR_REPLACE, req)
        }
    }
}
