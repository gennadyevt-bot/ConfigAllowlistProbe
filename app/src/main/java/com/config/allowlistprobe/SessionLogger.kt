package com.config.allowlistprobe

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Журнал сессии: подробные строки по каждому тесту + сводка.
 * Последняя сессия хранится во внутреннем хранилище (last-session.txt)
 * и не исчезает после закрытия приложения.
 */
class SessionLogger(private val ctx: Context) {
    private val sb = StringBuilder()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    val summary = LinkedHashMap<String, String>()   // TEST -> OK/FAIL/TIMEOUT
    val detail = StringBuilder()

    fun log(line: String) {
        val ts = fmt.format(Date())
        sb.append(ts).append(' ').append(line).append('\n')
    }

    fun test(name: String, result: String, block: (StringBuilder) -> Unit) {
        val b = StringBuilder()
        b.append("TEST ").append(name).append('\n')
        block(b)
        b.append("RESULT=").append(result).append('\n')
        summary[name] = result
        detail.append(b).append('\n')
        log(name + " -> " + result)
    }

    fun raw(block: StringBuilder.() -> Unit) {
        block(sb)
    }

    fun buildReport(): String {
        return "=== ConfigAllowlistProbe ===\n" +
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date()) + "\n\n" +
            sb.toString() + "\n=== DETAIL ===\n" + detail.toString()
    }

    fun saveLastSession() {
        try {
            ctx.openFileOutput("last-session.txt", Context.MODE_PRIVATE).use {
                it.write(buildReport().toByteArray())
            }
        } catch (_: Exception) {}
    }

    fun loadLastSession(): String {
        return try {
            File(ctx.filesDir, "last-session.txt").readText()
        } catch (_: Exception) {
            ""
        }
    }

    fun exportToDownloads(): String? {
        val stamp = SimpleDateFormat("yyyy-MM-dd_HHmm", Locale.US).format(Date())
        val fileName = "ConfigAllowlistProbe_$stamp.txt"
        val current = if (summary.isEmpty()) loadLastSession() else buildReport()
        val baseline = ctx.getSharedPreferences("baseline", Context.MODE_PRIVATE).getString("report", "") ?: ""
        val text = current + if (baseline.isNotEmpty()) "\n=== SAVED BASELINE ===\n$baseline" else ""
        return try {
            if (Build.VERSION.SDK_INT >= 29) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                    put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = ctx.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return null
                ctx.contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) } ?: return null
            } else {
                @Suppress("DEPRECATION")
                val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                dir.mkdirs()
                File(dir, fileName).writeText(text)
            }
            fileName
        } catch (e: Exception) {
            null
        }
    }
}
