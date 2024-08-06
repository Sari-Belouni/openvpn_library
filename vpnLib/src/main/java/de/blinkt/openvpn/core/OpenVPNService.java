/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

 package de.blinkt.openvpn.core;

 import android.Manifest.permission;
 import android.annotation.SuppressLint;
 import android.annotation.TargetApi;
 import android.app.Activity;
 import android.app.PendingIntent;
 import android.app.UiModeManager;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ShortcutManager;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.net.ConnectivityManager;
 import android.net.VpnService;
 import android.os.Binder;
 import android.os.Build;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.Handler.Callback;
 import android.os.IBinder;
 import android.os.Message;
 import android.os.ParcelFileDescriptor;
 import android.os.RemoteException;
 import android.system.OsConstants;
 import android.text.TextUtils;
 import android.util.Base64;
 import android.util.Log;
 import android.widget.Toast;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.RequiresApi;
 import androidx.localbroadcastmanager.content.LocalBroadcastManager;
 
 import java.io.IOException;
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.net.Inet6Address;
 import java.net.InetAddress;
 import java.net.UnknownHostException;
 import java.nio.charset.Charset;
 import java.text.DateFormat;
 import java.text.SimpleDateFormat;
 import java.util.Calendar;
 import java.util.Collection;
 import java.util.Locale;
 import java.util.Objects;
 import java.util.Vector;
 
 import de.blinkt.openvpn.DisconnectVPNActivity;
 import de.blinkt.openvpn.LaunchVPN;
 import de.blinkt.openvpn.R;
 import de.blinkt.openvpn.VpnProfile;
 import de.blinkt.openvpn.api.ExternalAppDatabase;
 import de.blinkt.openvpn.core.VpnStatus.ByteCountListener;
 import de.blinkt.openvpn.core.VpnStatus.StateListener;
 import de.blinkt.openvpn.utils.TotalTraffic;
 
 import static de.blinkt.openvpn.core.ConnectionStatus.LEVEL_CONNECTED;
 import static de.blinkt.openvpn.core.ConnectionStatus.LEVEL_WAITING_FOR_USER_INPUT;
 import static de.blinkt.openvpn.core.NetworkSpace.IpAddress;
 
 public class OpenVPNService extends VpnService implements StateListener, Callback, ByteCountListener, IOpenVPNServiceInternal {
 
     private String byteIn, byteOut;
     private String duration;
 
     public static final String START_SERVICE = "de.blinkt.openvpn.START_SERVICE";
     public static final String START_SERVICE_STICKY = "de.blinkt.openvpn.START_SERVICE_STICKY";
     public static final String ALWAYS_SHOW_NOTIFICATION = "de.blinkt.openvpn.NOTIFICATION_ALWAYS_VISIBLE";
     public static final String DISCONNECT_VPN = "de.blinkt.openvpn.DISCONNECT_VPN";
     public static final String VPNSERVICE_TUN = "vpnservice-tun";
     public final static String ORBOT_PACKAGE_NAME = "org.torproject.android";
     private static final String PAUSE_VPN = "de.blinkt.openvpn.PAUSE_VPN";
     private static final String RESUME_VPN = "de.blinkt.openvpn.RESUME_VPN";
 
     public static final String EXTRA_CHALLENGE_TXT = "de.blinkt.openvpn.core.CR_TEXT_CHALLENGE";
     public static final String EXTRA_CHALLENGE_OPENURL = "de.blinkt.openvpn.core.OPENURL_CHALLENGE";
 
     private static final int PRIORITY_MIN = -2;
     private static final int PRIORITY_DEFAULT = 0;
     private static final int PRIORITY_MAX = 2;
     private static Class<? extends Activity> mNotificationActivityClass;
     private final Vector<String> mDnslist = new Vector<>();
     private final NetworkSpace mRoutes = new NetworkSpace();
     private final NetworkSpace mRoutesv6 = new NetworkSpace();
     private final Object mProcessLock = new Object();
     private Thread mProcessThread = null;
     private VpnProfile mProfile;
     private String mDomain = null;
     private CIDRIP mLocalIP = null;
     private int mMtu;
     private String mLocalIPv6 = null;
     private DeviceStateReceiver mDeviceStateReceiver;
     private boolean mDisplayBytecount = false;
     private boolean mStarting = false;
     private long mConnecttime;
     private OpenVPNManagement mManagement;
 
     private final IBinder mBinder = new LocalBinder();
     private static String state = "";
     boolean flag = false;
     private String mLastTunCfg;
     private String mRemoteGW;
     private Handler guiHandler;
     private Toast mlastToast;
     private Runnable mOpenVPNThread;
 
     // From: http://stackoverflow.com/questions/3758606/how-to-convert-byte-size-into-human-readable-format-in-java
     public static String humanReadableByteCount(long bytes, boolean speed, Resources res) {
         if (speed)
             bytes = bytes * 8;
         int unit = speed ? 1000 : 1024;
 
         int exp = Math.max(0, Math.min((int) (Math.log(bytes) / Math.log(unit)), 3));
 
         float bytesUnit = (float) (bytes / Math.pow(unit, exp));
 
         if (speed)
             switch (exp) {
                 case 0:
                     return res.getString(R.string.bits_per_second, bytesUnit);
                 case 1:
                     return res.getString(R.string.kbits_per_second, bytesUnit);
                 case 2:
                     return res.getString(R.string.mbits_per_second, bytesUnit);
                 default:
                     return res.getString(R.string.gbits_per_second, bytesUnit);
             }
         else
             switch (exp) {
                 case 0:
                     return res.getString(R.string.volume_byte, bytesUnit);
                 case 1:
                     return res.getString(R.string.volume_kbyte, bytesUnit);
                 case 2:
                     return res.getString(R.string.volume_mbyte, bytesUnit);
                 default:
                     return res.getString(R.string.volume_gbyte, bytesUnit);
 
             }
     }
 
     /**
      * Sets the activity which should be opened when tapped on the permanent notification tile.
      *
      * @param activityClass The activity class to open
      */
     public static void setNotificationActivityClass(Class<? extends Activity> activityClass) {
         mNotificationActivityClass = activityClass;
     }
 
     @Override
     public void addAllowedExternalApp(String packagename) throws RemoteException {
         ExternalAppDatabase extapps = new ExternalAppDatabase(OpenVPNService.this);
         extapps.addApp(packagename);
     }
 
     @Override
     public boolean isAllowedExternalApp(String packagename) throws RemoteException {
         ExternalAppDatabase extapps = new ExternalAppDatabase(OpenVPNService.this);
         return extapps.checkRemoteActionPermission(this, packagename);
     }
 
     @Override
     public void challengeResponse(String response) throws RemoteException {
         if (mManagement != null) {
             String b64response = Base64.encodeToString(response.getBytes(Charset.forName("UTF-8")), Base64.DEFAULT);
             mManagement.sendCRResponse(b64response);
         }
     }
 
     @Override
     public IBinder onBind(Intent intent) {
         String action = intent.getAction();
         if (action != null && action.equals(START_SERVICE))
             return mBinder;
         else
             return super.onBind(intent);
     }
 
     @Override
     public void onRevoke() {
         VpnStatus.logError(R.string.permission_revoked);
         mManagement.stopVPN(false);
         endVpnService();
     }
 
     // Similar to revoke but do not try to stop process
     public void openvpnStopped() {
         endVpnService();
     }
 
     public void endVpnService() {
         synchronized (mProcessLock) {
             mProcessThread = null;
         }
         VpnStatus.removeByteCountListener(this);
         unregisterDeviceStateReceiver();
         ProfileManager.setConntectedVpnProfileDisconnected(this);
         mOpenVPNThread = null;
         if (!mStarting) {
             stopSelf();
             VpnStatus.removeStateListener(this);
         }
     }
 
     @Override
     public IBinder asBinder() {
         return mBinder;
     }
 
     @Override
     public void onCreate() {
         super.onCreate();
     }
 
     @Override
     public void onDestroy() {
         sendMessage("DISCONNECTED");
         synchronized (mProcessLock) {
             if (mProcessThread != null) {
                 mManagement.stopVPN(true);
             }
         }
 
         try {
             if (mDeviceStateReceiver != null) {
                 this.unregisterReceiver(mDeviceStateReceiver);
             }
         } catch (IllegalArgumentException ignored) {
             // I don't know why  this happens:
             // java.lang.IllegalArgumentException: Receiver not registered: de.blinkt.openvpn.NetworkSateReceiver@41a61a10
             // Ignore for now ...
         }
         // Just in case unregister for state
         VpnStatus.removeStateListener(this);
         VpnStatus.flushLog();
     }
 
     private String getTunConfigString() {
         // The format of the string is not important, only that
         // two identical configurations produce the same result
         String cfg = "TUNCFG UNQIUE STRING ips:";
 
         if (mLocalIP != null)
             cfg += mLocalIP.toString();
         if (mLocalIPv6 != null)
             cfg += mLocalIPv6;
 
 
         cfg += "routes: " + TextUtils.join("|", mRoutes.getNetworks(true)) + TextUtils.join("|", mRoutesv6.getNetworks(true));
         cfg += "excl. routes:" + TextUtils.join("|", mRoutes.getNetworks(false)) + TextUtils.join("|", mRoutesv6.getNetworks(false));
         cfg += "dns: " + TextUtils.join("|", mDnslist);
         cfg += "domain: " + mDomain;
         cfg += "mtu: " + mMtu;
         return cfg;
     }
 
     public ParcelFileDescriptor openTun() {
 
         //Debug.startMethodTracing(getExternalFilesDir(null).toString() + "/opentun.trace", 40* 1024 * 1024);
 
         Builder builder = new Builder();
 
         VpnStatus.logInfo(R.string.last_openvpn_tun_config);
 
         boolean allowUnsetAF = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && !mProfile.mBlockUnusedAddressFamilies;
         if (allowUnsetAF) {
             allowAllAFFamilies(builder);
         }
 
         if (mLocalIP == null && mLocalIPv6 == null) {
             VpnStatus.logError(getString(R.string.opentun_no_ipaddr));
             return null;
         }
 
         if (mLocalIP != null) {
             // OpenVPN3 manages excluded local networks by callback
             if (!VpnProfile.doUseOpenVPN3(this))
                 addLocalNetworksToRoutes();
             try {
                 builder.addAddress(mLocalIP.mIp, mLocalIP.len);
             } catch (IllegalArgumentException iae) {
                 VpnStatus.logError(R.string.dns_add_error, mLocalIP, iae.getLocalizedMessage());
                 return null;
             }
         }
 
         if (mLocalIPv6 != null) {
             String[] ipv6parts = mLocalIPv6.split("/");
             try {
                 builder.addAddress(ipv6parts[0], Integer.parseInt(ipv6parts[1]));
             } catch (IllegalArgumentException iae) {
                 VpnStatus.logError(R.string.ip_add_error, mLocalIPv6, iae.getLocalizedMessage());
                 return null;
             }
 
         }
 
 
         for (String dns : mDnslist) {
             try {
                 builder.addDnsServer(dns);
             } catch (IllegalArgumentException iae) {
                 VpnStatus.logError(R.string.dns_add_error, dns, iae.getLocalizedMessage());
             }
         }
 
         String release = Build.VERSION.RELEASE;
         if ((Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT && !release.startsWith("4.4.3")
                 && !release.startsWith("4.4.4") && !release.startsWith("4.4.5") && !release.startsWith("4.4.6"))
                 && mMtu < 1280) {
             VpnStatus.logInfo(String.format(Locale.US, "Forcing MTU to 1280 instead of %d to workaround Android Bug #70916", mMtu));
             builder.setMtu(1280);
         } else {
             builder.setMtu(mMtu);
         }
 
         Collection<IpAddress> positiveIPv4Routes = mRoutes.getPositiveIPList();
         Collection<IpAddress> positiveIPv6Routes = mRoutesv6.getPositiveIPList();
 
         if ("samsung".equals(Build.BRAND) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && mDnslist.size() >= 1) {
             // Check if the first DNS Server is in the VPN range
             try {
                 IpAddress dnsServer = new IpAddress(new CIDRIP(mDnslist.get(0), 32), true);
                 boolean dnsIncluded = false;
                 for (IpAddress net : positiveIPv4Routes) {
                     if (net.containsNet(dnsServer)) {
                         dnsIncluded = true;
                     }
                 }
                 if (!dnsIncluded) {
                     String samsungwarning = String.format("Warning Samsung Android 5.0+ devices ignore DNS servers outside the VPN range. To enable DNS resolution a route to your DNS Server (%s) has been added.", mDnslist.get(0));
                     VpnStatus.logWarning(samsungwarning);
                     positiveIPv4Routes.add(dnsServer);
                 }
             } catch (Exception e) {
                 // If it looks like IPv6 ignore error
                 if (!mDnslist.get(0).contains(":"))
                     VpnStatus.logError("Error parsing DNS Server IP: " + mDnslist.get(0));
             }
         }
 
         IpAddress multicastRange = new IpAddress(new CIDRIP("224.0.0.0", 3), true);
 
         for (IpAddress route : positiveIPv4Routes) {
             try {
 
                 if (multicastRange.containsNet(route))
                     VpnStatus.logDebug(R.string.ignore_multicast_route, route.toString());
                 else
                     builder.addRoute(route.getIPv4Address(), route.networkMask);
             } catch (IllegalArgumentException ia) {
                 VpnStatus.logError(getString(R.string.route_rejected) + route + " " + ia.getLocalizedMessage());
             }
         }
 
         for (IpAddress route6 : positiveIPv6Routes) {
             try {
                 builder.addRoute(route6.getIPv6Address(), route6.networkMask);
             } catch (IllegalArgumentException ia) {
                 VpnStatus.logError(getString(R.string.route_rejected) + route6 + " " + ia.getLocalizedMessage());
             }
         }
 
 
         if (mDomain != null)
             builder.addSearchDomain(mDomain);
 
         String ipv4info;
         String ipv6info;
         if (allowUnsetAF) {
             ipv4info = "(not set, allowed)";
             ipv6info = "(not set, allowed)";
         } else {
             ipv4info = "(not set)";
             ipv6info = "(not set)";
         }
 
         int ipv4len;
         if (mLocalIP != null) {
             ipv4len = mLocalIP.len;
             ipv4info = mLocalIP.mIp;
         } else {
             ipv4len = -1;
         }
 
         if (mLocalIPv6 != null) {
             ipv6info = mLocalIPv6;
         }
 
         if ((!mRoutes.getNetworks(false).isEmpty() || !mRoutesv6.getNetworks(false).isEmpty()) && isLockdownEnabledCompat()) {
             VpnStatus.logInfo("VPN lockdown enabled (do not allow apps to bypass VPN) enabled. Route exclusion will not allow apps to bypass VPN (e.g. bypass VPN for local networks)");
         }
         if (mDomain != null) builder.addSearchDomain(mDomain);
         VpnStatus.logInfo(R.string.local_ip_info, ipv4info, ipv4len, ipv6info, mMtu);
         VpnStatus.logInfo(R.string.dns_server_info, TextUtils.join(", ", mDnslist), mDomain);
         VpnStatus.logInfo(R.string.routes_info_incl, TextUtils.join(", ", mRoutes.getNetworks(true)), TextUtils.join(", ", mRoutesv6.getNetworks(true)));
         VpnStatus.logInfo(R.string.routes_info_excl, TextUtils.join(", ", mRoutes.getNetworks(false)), TextUtils.join(", ", mRoutesv6.getNetworks(false)));
         VpnStatus.logDebug(R.string.routes_debug, TextUtils.join(", ", positiveIPv4Routes), TextUtils.join(", ", positiveIPv6Routes));
         if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
             setAllowedVpnPackages(builder);
         }
         if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
             // VPN always uses the default network
             builder.setUnderlyingNetworks(null);
         }
 
 
         String session = mProfile.mName;
         if (mLocalIP != null && mLocalIPv6 != null)
             session = getString(R.string.session_ipv6string, session, mLocalIP, mLocalIPv6);
         else if (mLocalIP != null)
             session = getString(R.string.session_ipv4string, session, mLocalIP);
         else
             session = getString(R.string.session_ipv4string, session, mLocalIPv6);
 
         builder.setSession(session);
 
         // No DNS Server, log a warning
         if (mDnslist.size() == 0)
             VpnStatus.logInfo(R.string.warn_no_dns);
 
         mLastTunCfg = getTunConfigString();
 
         // Reset information
         mDnslist.clear();
         mRoutes.clear();
         mRoutesv6.clear();
         mLocalIP = null;
         mLocalIPv6 = null;
         mDomain = null;
 
         builder.setConfigureIntent(null);
 
         try {
             //Debug.stopMethodTracing();
             ParcelFileDescriptor tun = builder.establish();
             if (tun == null)
                 throw new NullPointerException("Android establish() method returned null (Really broken network configuration?)");
             return tun;
         } catch (Exception e) {
             VpnStatus.logError(R.string.tun_open_error);
             VpnStatus.logError(getString(R.string.error) + e.getLocalizedMessage());
             if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                 VpnStatus.logError(R.string.tun_error_helpful);
             }
             return null;
         }
 
     }
 
     private boolean isLockdownEnabledCompat() {
         if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
             return isLockdownEnabled();
         } else {
             /* We cannot determine this, return false */
             return false;
         }
 
     }
 
     @TargetApi(Build.VERSION_CODES.LOLLIPOP)
     private void allowAllAFFamilies(Builder builder) {
         builder.allowFamily(OsConstants.AF_INET);
         builder.allowFamily(OsConstants.AF_INET6);
     }
 
     private void addLocalNetworksToRoutes() {
         for (String net : NetworkUtils.getLocalNetworks(this, false)) {
             String[] netparts = net.split("/");
             String ipAddr = netparts[0];
             int netMask = Integer.parseInt(netparts[1]);
             if (ipAddr.equals(mLocalIP.mIp))
                 continue;
 
             if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT && !mProfile.mAllowLocalLAN) {
                 mRoutes.addIPSplit(new CIDRIP(ipAddr, netMask), true);
 
             } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT && mProfile.mAllowLocalLAN)
                 mRoutes.addIP(new CIDRIP(ipAddr, netMask), false);
         }
 
         // IPv6 is Lollipop+ only so we can skip the lower than KITKAT case
         if (mProfile.mAllowLocalLAN) {
             for (String net : NetworkUtils.getLocalNetworks(this, true)) {
                 addRoutev6(net, false);
             }
         }
 
 
     }
 
     @TargetApi(Build.VERSION_CODES.LOLLIPOP)
     private void setAllowedVpnPackages(Builder builder) {
         boolean profileUsesOrBot = false;
 
         for (Connection c : mProfile.mConnections) {
             if (c.mProxyType == Connection.ProxyType.ORBOT)
                 profileUsesOrBot = true;
         }
 
         if (profileUsesOrBot)
             VpnStatus.logDebug("VPN Profile uses at least one server entry with Orbot. Setting up VPN so that OrBot is not redirected over VPN.");
 
         boolean atLeastOneAllowedApp = false;
 
         if (mProfile.mAllowedAppsVpnAreDisallowed && profileUsesOrBot) {
             try {
                 builder.addDisallowedApplication(ORBOT_PACKAGE_NAME);
             } catch (PackageManager.NameNotFoundException e) {
                 VpnStatus.logDebug("Orbot not installed?");
             }
         }
 
         for (String pkg : mProfile.mAllowedAppsVpn) {
             try {
                 if (mProfile.mAllowedAppsVpnAreDisallowed) {
                     builder.addDisallowedApplication(pkg);
                 } else {
                     if (!(profileUsesOrBot && pkg.equals(ORBOT_PACKAGE_NAME))) {
                         builder.addAllowedApplication(pkg);
                         atLeastOneAllowedApp = true;
                     }
                 }
             } catch (PackageManager.NameNotFoundException e) {
                 mProfile.mAllowedAppsVpn.remove(pkg);
                 VpnStatus.logInfo(R.string.app_no_longer_exists, pkg);
             }
         }
 
         if (!mProfile.mAllowedAppsVpnAreDisallowed && !atLeastOneAllowedApp) {
             VpnStatus.logDebug(R.string.no_allowed_app, getPackageName());
             try {
                 builder.addAllowedApplication(getPackageName());
             } catch (PackageManager.NameNotFoundException e) {
                 VpnStatus.logError("This should not happen: " + e.getLocalizedMessage());
             }
         }
 
         if (mProfile.mAllowedAppsVpnAreDisallowed) {
             VpnStatus.logDebug(R.string.disallowed_vpn_apps_info, TextUtils.join(", ", mProfile.mAllowedAppsVpn));
         } else {
             VpnStatus.logDebug(R.string.allowed_vpn_apps_info, TextUtils.join(", ", mProfile.mAllowedAppsVpn));
         }
 
         if (mProfile.mAllowAppVpnBypass) {
             builder.allowBypass();
             VpnStatus.logDebug("Apps may bypass VPN");
         }
     }
 
     public void addDNS(String dns) {
         mDnslist.add(dns);
     }
 
     public void setDomain(String domain) {
         if (mDomain == null) {
             mDomain = domain;
         }
     }
 
     /**
      * Route that is always included, used by the v3 core
      */
     public void addRoute(CIDRIP route, boolean include) {
         mRoutes.addIP(route, include);
     }
 
     public void addRoute(String dest, String mask, String gateway, String device) {
         CIDRIP route = new CIDRIP(dest, mask);
         boolean include = isAndroidTunDevice(device);
 
         IpAddress gatewayIP = new IpAddress(new CIDRIP(gateway, 32), false);
 
         if (mLocalIP == null) {
             VpnStatus.logError("Local IP address unset and received. Neither pushed server config nor local config specifies an IP addresses. Opening tun device is most likely going to fail.");
             return;
         }
         IpAddress localNet = new IpAddress(mLocalIP, true);
         if (localNet.containsNet(gatewayIP))
             include = true;
 
         if (gateway != null &&
                 (gateway.equals("255.255.255.255") || gateway.equals(mRemoteGW)))
             include = true;
 
 
         if (route.len == 32 && !mask.equals("255.255.255.255")) {
             VpnStatus.logWarning(R.string.route_not_cidr, dest, mask);
         }
 
         if (route.normalise())
             VpnStatus.logWarning(R.string.route_not_netip, dest, route.len, route.mIp);
 
         mRoutes.addIP(route, include);
     }
 
     public void addRoutev6(String network, String device) {
         // Tun is opened after ROUTE6, no device name may be present
         boolean included = isAndroidTunDevice(device);
         addRoutev6(network, included);
     }
 
     public void addRoutev6(String network, boolean included) {
         String[] v6parts = network.split("/");
 
         try {
             Inet6Address ip = (Inet6Address) InetAddress.getAllByName(v6parts[0])[0];
             int mask = Integer.parseInt(v6parts[1]);
             mRoutesv6.addIPv6(ip, mask, included);
 
         } catch (UnknownHostException e) {
             VpnStatus.logException(e);
         }
 
 
     }
 
     private boolean isAndroidTunDevice(String device) {
         return device != null &&
                 (device.startsWith("tun") || "(null)".equals(device) || VPNSERVICE_TUN.equals(device));
     }
 
     public void setMtu(int mtu) {
         mMtu = mtu;
     }
 
     public void setLocalIP(CIDRIP cdrip) {
         mLocalIP = cdrip;
     }
 
     public void setLocalIP(String local, String netmask, int mtu, String mode) {
         mLocalIP = new CIDRIP(local, netmask);
         mMtu = mtu;
         mRemoteGW = null;
 
         long netMaskAsInt = CIDRIP.getInt(netmask);
 
         if (mLocalIP.len == 32 && !netmask.equals("255.255.255.255")) {
             // get the netmask as IP
 
             int masklen;
             long mask;
             if ("net30".equals(mode)) {
                 masklen = 30;
                 mask = 0xfffffffc;
             } else {
                 masklen = 31;
                 mask = 0xfffffffe;
             }
 
             // Netmask is Ip address +/-1, assume net30/p2p with small net
             if ((netMaskAsInt & mask) == (mLocalIP.getInt() & mask)) {
                 mLocalIP.len = masklen;
             } else {
                 mLocalIP.len = 32;
                 if (!"p2p".equals(mode))
                     VpnStatus.logWarning(R.string.ip_not_cidr, local, netmask, mode);
             }
         }
         if (("p2p".equals(mode) && mLocalIP.len < 32) || ("net30".equals(mode) && mLocalIP.len < 30)) {
             VpnStatus.logWarning(R.string.ip_looks_like_subnet, local, netmask, mode);
         }
 
 
         /* Workaround for Lollipop, it  does not route traffic to the VPNs own network mask */
         if (mLocalIP.len <= 31 && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
             CIDRIP interfaceRoute = new CIDRIP(mLocalIP.mIp, mLocalIP.len);
             interfaceRoute.normalise();
             addRoute(interfaceRoute, true);
         }
 
 
         // Configurations are sometimes really broken...
         mRemoteGW = netmask;
     }
 
     public void setLocalIPv6(String ipv6addr) {
         mLocalIPv6 = ipv6addr;
     }
 
     @Override
     public void updateState(String state, String logmessage, int resid, ConnectionStatus level, Intent intent) {
         // If the process is not running, ignore any state,
         // Notification should be invisible in this state
 
         doSendBroadcast(state, level);
         if (mProcessThread == null)
             return;
 
         {
             if (level == LEVEL_CONNECTED) {
                 mDisplayBytecount = true;
                 mConnecttime = System.currentTimeMillis();
             } else {
                 mDisplayBytecount = false;
             }
 
         }
     }
 
     @Override
     public void setConnectedVPN(String uuid) {
     }
 
     private void doSendBroadcast(String state, ConnectionStatus level) {
         Intent vpnstatus = new Intent();
         vpnstatus.setAction("de.blinkt.openvpn.VPN_STATUS");
         vpnstatus.putExtra("status", level.toString());
         vpnstatus.putExtra("detailstatus", state);
         sendBroadcast(vpnstatus, permission.ACCESS_NETWORK_STATE);
         sendMessage(state);
     }
 
     long c = Calendar.getInstance().getTimeInMillis();
     long time;
     int lastPacketReceive = 0;
     String seconds = "0", minutes, hours;
 
     @Override
     public void updateByteCount(long in, long out, long diffIn, long diffOut) {
         TotalTraffic.calcTraffic(this, in, out, diffIn, diffOut);
         if (mDisplayBytecount) {
             String netstat = String.format(getString(R.string.statusline_bytecount),
                     humanReadableByteCount(in, false, getResources()),
                     humanReadableByteCount(diffIn / OpenVPNManagement.mBytecountInterval, true, getResources()),
                     humanReadableByteCount(out, false, getResources()),
                     humanReadableByteCount(diffOut / OpenVPNManagement.mBytecountInterval, true, getResources()));
 
             byteIn = String.valueOf(in);
             byteOut = String.valueOf(out);
 
             if(byteIn.isEmpty() ||byteIn.trim().length() == 0) byteIn = "0";
             if(byteOut.isEmpty() || byteOut.trim().length() == 0) byteOut = "0";
 
             time = Calendar.getInstance().getTimeInMillis() - c;
             lastPacketReceive = Integer.parseInt(convertTwoDigit((int) (time / 1000) % 60)) - Integer.parseInt(seconds);
 
             Calendar connectedOn = Calendar.getInstance();
             connectedOn.setTimeInMillis(c);
 
             @SuppressLint("SimpleDateFormat") DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
             duration = dateFormat.format(connectedOn.getTime());
             lastPacketReceive = checkPacketReceive(lastPacketReceive);
             sendMessage(duration, String.valueOf(lastPacketReceive), byteIn, byteOut);
         }
 
     }
 
     public int checkPacketReceive(int value) {
         value -= 2;
         if (value < 0) return 0;
         else return value;
     }
 
     public String convertTwoDigit(int value) {
         if (value < 10) return "0" + value;
         else return value + "";
     }
 
     @Override
     public boolean handleMessage(Message msg) {
         Runnable r = msg.getCallback();
         if (r != null) {
             r.run();
             return true;
         } else {
             return false;
         }
     }
 
     public OpenVPNManagement getManagement() {
         return mManagement;
     }
 
     public String getTunReopenStatus() {
         String currentConfiguration = getTunConfigString();
         if (currentConfiguration.equals(mLastTunCfg)) {
             return "NOACTION";
         } else {
             String release = Build.VERSION.RELEASE;
             if (Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT && !release.startsWith("4.4.3")
                     && !release.startsWith("4.4.4") && !release.startsWith("4.4.5") && !release.startsWith("4.4.6"))
                 // There will be probably no 4.4.4 or 4.4.5 version, so don't waste effort to do parsing here
                 return "OPEN_AFTER_CLOSE";
             else
                 return "OPEN_BEFORE_CLOSE";
         }
     }
 
     public void requestInputFromUser(int resid, String needed) {
         VpnStatus.updateStateString("NEED", "need " + needed, resid, LEVEL_WAITING_FOR_USER_INPUT);
     }
 
     public void trigger_sso(String info) {
         String method = info.split(":", 2)[0];
 
         Intent intent;
 
         int reason;
         if (method.equals("CR_TEXT")) {
             String challenge = info.split(":", 2)[1];
             reason = R.string.crtext_requested;
 
             intent = new Intent();
             intent.setComponent(new ComponentName(this, getPackageName() + ".activities.CredentialsPopup"));
 
             intent.putExtra(EXTRA_CHALLENGE_TXT, challenge);
 
         } else {
             VpnStatus.logError("Unknown SSO method found: " + method);
             return;
         }
 
         VpnStatus.updateStateString("USER_INPUT", "waiting for user input", reason, LEVEL_WAITING_FOR_USER_INPUT, intent);
     }
 
     //sending message to main activity
     private void sendMessage(String state) {
         Intent intent = new Intent("connectionState");
         intent.putExtra("state", state);
         OpenVPNService.state = state;
         LocalBroadcastManager.getInstance(getApplicationContext()).sendBroadcast(intent);
     }
 
     //sending message to main activity
     private void sendMessage(String duration, String lastPacketReceive, String byteIn, String byteOut) {
         Intent intent = new Intent("connectionState");
         intent.putExtra("duration", duration);
         intent.putExtra("lastPacketReceive", lastPacketReceive);
         intent.putExtra("byteIn", byteIn);
         intent.putExtra("byteOut", byteOut);
         LocalBroadcastManager.getInstance(getApplicationContext()).sendBroadcast(intent);
     }
 
     public class LocalBinder extends Binder {
         public OpenVPNService getService() {
             // Return this instance of LocalService so clients can call public methods
             return OpenVPNService.this;
         }
     }
 
     public static String getStatus() {//it will be call from mainactivity for get current status
         return state;
     }
 
     public static void setDefaultStatus() {
         state = "idle";
     }
 
     public boolean isConnected() {
         return flag;
     }
 }
 