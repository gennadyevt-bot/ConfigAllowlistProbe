package com.config.allowlistprobe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyManager
import java.net.Inet4Address
import java.net.Inet6Address

data class NetSnapshot(
    val handle: Long, val transport: String,
    val validated: String, val internet: String, val metered: String, val vpn: String,
    val ipv4: String, val ipv6: String, val dns: String, val routes: String,
    val networkType: String, val voiceNetworkType: String,
    val operator: String, val mccMnc: String, val roaming: String,
    val signalLevel: String, val subscriptionId: String, val cellInfo: String
) {
    fun core(): Map<String, String> = linkedMapOf(
        "handle" to handle.toString(), "transport" to transport,
        "ipv4" to ipv4, "ipv6" to ipv6, "dns" to dns, "routes" to routes,
        "networkType" to networkType, "operator" to operator, "mccMnc" to mccMnc
    )

    fun describe(): String {
        val sb = StringBuilder()
        sb.append("handle=").append(handle).append('\n')
        sb.append("transport=").append(transport).append('\n')
        sb.append("validated=").append(validated).append('\n')
        sb.append("internet=").append(internet).append('\n')
        sb.append("metered=").append(metered).append('\n')
        sb.append("vpn transport=").append(vpn).append('\n')
        sb.append("IPv4=").append(ipv4).append('\n')
        sb.append("IPv6=").append(ipv6).append('\n')
        sb.append("DNS=").append(dns).append('\n')
        sb.append("routes=").append(routes).append('\n')
        sb.append("networkType=").append(networkType).append('\n')
        sb.append("voiceNetworkType=").append(voiceNetworkType).append('\n')
        sb.append("operator=").append(operator).append('\n')
        sb.append("mccMnc=").append(mccMnc).append('\n')
        sb.append("roaming=").append(roaming).append('\n')
        sb.append("signalLevel=").append(signalLevel).append('\n')
        sb.append("subscriptionId=").append(subscriptionId).append('\n')
        sb.append("cellInfo=").append(cellInfo).append('\n')
        return sb.toString()
    }

    fun diff(other: NetSnapshot): List<String> {
        val changes = ArrayList<String>()
        val b = other.core()
        for ((k, v) in core()) {
            val ov = b[k] ?: "?"
            if (v != ov) changes.add("$k: $v -> $ov")
        }
        return changes
    }

    companion object {
        private fun safe(f: () -> Any?): String =
            try { f()?.toString() ?: "?" } catch (_: Exception) { "?" }

        private fun describeCell(c: CellInfo): String = try {
            when {
                c is CellInfoLte -> buildString {
                    append("LTE ci=").append(safe { c.cellIdentity.ci })
                    append(" tac=").append(safe { c.cellIdentity.tac })
                    append(" pci=").append(safe { c.cellIdentity.pci })
                    append(" earfcn=").append(safe { c.cellIdentity.earfcn })
                    if (Build.VERSION.SDK_INT >= 29) append(" rsrp=").append(safe { c.cellSignalStrength.rsrp })
                }
                Build.VERSION.SDK_INT >= 29 && c is CellInfoNr -> buildString {
                    append("NR nci=").append(safe { c.cellIdentity.nci })
                    append(" tac=").append(safe { c.cellIdentity.tac })
                    append(" pci=").append(safe { c.cellIdentity.pci })
                    append(" nrarfcn=").append(safe { c.cellIdentity.nrarfcn })
                }
                c is CellInfoWcdma -> buildString {
                    append("WCDMA cid=").append(safe { c.cellIdentity.cid })
                    append(" lac=").append(safe { c.cellIdentity.lac })
                    append(" psc=").append(safe { c.cellIdentity.psc })
                    append(" uarfcn=").append(safe { c.cellIdentity.uarfcn })
                }
                c is CellInfoGsm -> buildString {
                    append("GSM cid=").append(safe { c.cellIdentity.cid })
                    append(" lac=").append(safe { c.cellIdentity.lac })
                    append(" arfcn=").append(safe { c.cellIdentity.arfcn })
                }
                else -> c.javaClass.simpleName
            }
        } catch (_: Exception) { c.javaClass.simpleName }

        fun capture(ctx: Context, cm: ConnectivityManager,
                    transportName: (Network?) -> String): NetSnapshot {
            val n: Network? = cm.activeNetwork
            val caps = n?.let { cm.getNetworkCapabilities(it) }
            val lp = n?.let { cm.getLinkProperties(it) }
            val v4 = lp?.linkAddresses
                ?.filter { it.address is Inet4Address }
                ?.joinToString(",") { it.address.hostAddress ?: "?" } ?: "none"
            val v6 = lp?.linkAddresses
                ?.filter { it.address is Inet6Address }
                ?.joinToString(",") { it.address.hostAddress?.split("%")?.get(0) ?: "?" } ?: "none"
            val dns = lp?.dnsServers?.joinToString(",") { it.hostAddress ?: "?" } ?: "none"
            val routes = lp?.routes?.joinToString(",") { it.destination.toString() } ?: "none"

            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            var networkType = "UNAVAILABLE"
            var voiceNetworkType = "UNAVAILABLE"
            var operator = "?"
            var mccMnc = "?"
            var roaming = "?"
            var signalLevel = "?"
            var subscriptionId = "?"
            var cellInfoStr = "CELL_INFO_UNAVAILABLE"

            if (tm != null) {
                operator = try { tm.networkOperatorName ?: "?" } catch (_: Exception) { "?" }
                mccMnc = try { tm.networkOperator ?: "?" } catch (_: Exception) { "?" }
                roaming = try { tm.isNetworkRoaming.toString() } catch (_: Exception) { "?" }
                networkType = try {
                    when (tm.dataNetworkType) {
                        TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
                        TelephonyManager.NETWORK_TYPE_NR -> "NR"
                        TelephonyManager.NETWORK_TYPE_HSPAP, TelephonyManager.NETWORK_TYPE_HSPA,
                        TelephonyManager.NETWORK_TYPE_HSDPA, TelephonyManager.NETWORK_TYPE_UMTS,
                        TelephonyManager.NETWORK_TYPE_WCDMA -> "3G"
                        TelephonyManager.NETWORK_TYPE_EDGE, TelephonyManager.NETWORK_TYPE_GPRS -> "2G"
                        else -> "TYPE_" + tm.dataNetworkType
                    }
                } catch (e: SecurityException) { "PERMISSION_REQUIRED" }
                  catch (_: Exception) { "UNKNOWN" }
                if (Build.VERSION.SDK_INT >= 30) {
                    voiceNetworkType = try { tm.voiceNetworkType.toString() }
                        catch (e: SecurityException) { "PERMISSION_REQUIRED" }
                        catch (_: Exception) { "UNKNOWN" }
                }
                if (Build.VERSION.SDK_INT >= 28) {
                    signalLevel = try { tm.signalStrength?.level?.toString() ?: "?" }
                        catch (_: Exception) { "?" }
                }
                if (Build.VERSION.SDK_INT >= 30) {
                    subscriptionId = try { tm.subscriptionId.toString() } catch (_: Exception) { "?" }
                }
                cellInfoStr = try {
                    val list = tm.allCellInfo
                    if (list.isNullOrEmpty()) "CELL_INFO_UNAVAILABLE"
                    else list.joinToString("; ") { describeCell(it) }
                } catch (e: SecurityException) { "CELL_INFO_UNAVAILABLE" }
                  catch (_: Exception) { "CELL_INFO_UNAVAILABLE" }
            }

            return NetSnapshot(
                handle = n?.networkHandle ?: -1L,
                transport = transportName(n),
                validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)?.toString() ?: "?",
                internet = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)?.toString() ?: "?",
                metered = caps?.let { (!it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)).toString() } ?: "?",
                vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)?.toString() ?: "?",
                ipv4 = v4, ipv6 = v6, dns = dns, routes = routes,
                networkType = networkType, voiceNetworkType = voiceNetworkType,
                operator = operator, mccMnc = mccMnc, roaming = roaming,
                signalLevel = signalLevel, subscriptionId = subscriptionId, cellInfo = cellInfoStr
            )
        }
    }
}
