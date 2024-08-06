package de.blinkt.openvpn.core;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import androidx.annotation.RequiresApi;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Vector;

import de.blinkt.openvpn.VpnProfile;
import de.blinkt.openvpn.api.ExternalAppDatabase;
import de.blinkt.openvpn.core.VpnStatus.ByteCountListener;
import de.blinkt.openvpn.core.VpnStatus.StateListener;

public class OpenVPNService extends VpnService implements StateListener, ByteCountListener, IOpenVPNServiceInternal {

    private VpnProfile mProfile;
    private OpenVPNManagement mManagement;
    private Thread mProcessThread = null;
    private boolean mStarting = false;
    private final Object mProcessLock = new Object();
    private static String state = "";
    private String mLastTunCfg;
    private Handler guiHandler;
    private Runnable mOpenVPNThread;
    private final IBinder mBinder = new LocalBinder();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        VpnStatus.addStateListener(this);
        VpnStatus.addByteCountListener(this);

        guiHandler = new Handler(getMainLooper());

        if (intent != null && intent.hasExtra(getPackageName() + ".profileUUID")) {
            String profileUUID = intent.getStringExtra(getPackageName() + ".profileUUID");
            int profileVersion = intent.getIntExtra(getPackageName() + ".profileVersion", 0);
            mProfile = ProfileManager.get(this, profileUUID, profileVersion, 100);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N_MR1) {
                updateShortCutUsage(mProfile);
            }

        } else {
            mProfile = ProfileManager.getLastConnectedProfile(this);
            VpnStatus.logInfo(R.string.service_restarted);

            if (mProfile == null) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            mProfile.checkForRestart(this);
        }

        if (mProfile == null) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        new Thread(this::startOpenVPN).start();

        ProfileManager.setConnectedVpnProfile(this, mProfile);
        VpnStatus.setConnectedVPNProfile(mProfile.getUUIDString());

        return START_STICKY;
    }

    @RequiresApi(Build.VERSION_CODES.N_MR1)
    private void updateShortCutUsage(VpnProfile profile) {
        if (profile == null)
            return;
        getSystemService(ShortcutManager.class).reportShortcutUsed(profile.getUUIDString());
    }

    private void startOpenVPN() {
        try {
            mProfile.writeConfigFile(this);
        } catch (IOException e) {
            VpnStatus.logException("Error writing config file", e);
            endVpnService();
            return;
        }
        String nativeLibraryDirectory = getApplicationInfo().nativeLibraryDir;
        String tmpDir;
        try {
            tmpDir = getApplication().getCacheDir().getCanonicalPath();
        } catch (IOException e) {
            e.printStackTrace();
            tmpDir = "/tmp";
        }

        String[] argv = VPNLaunchHelper.buildOpenvpnArgv(this);

        mStarting = true;
        stopOldOpenVPNProcess();
        mStarting = false;

        boolean useOpenVPN3 = VpnProfile.doUseOpenVPN3(this);

        if (!useOpenVPN3) {
            OpenVpnManagementThread ovpnManagementThread = new OpenVpnManagementThread(mProfile, this);
            if (ovpnManagementThread.openManagementInterface(this)) {
                Thread mSocketManagerThread = new Thread(ovpnManagementThread, "OpenVPNManagementThread");
                mSocketManagerThread.start();
                mManagement = ovpnManagementThread;
                VpnStatus.logInfo("started Socket Thread");
            } else {
                endVpnService();
                return;
            }
        }

        Runnable processThread;
        if (useOpenVPN3) {
            OpenVPNManagement mOpenVPN3 = instantiateOpenVPN3Core();
            processThread = (Runnable) mOpenVPN3;
            mManagement = mOpenVPN3;
        } else {
            processThread = new OpenVPNThread(this, argv, nativeLibraryDirectory, tmpDir);
            mOpenVPNThread = processThread;
        }

        synchronized (mProcessLock) {
            mProcessThread = new Thread(processThread, "OpenVPNProcessThread");
            mProcessThread.start();
        }

        new Handler(getMainLooper()).post(() -> {
            if (mDeviceStateReceiver != null)
                unregisterDeviceStateReceiver();

            registerDeviceStateReceiver(mManagement);
        });
    }

    private void stopOldOpenVPNProcess() {
        if (mManagement != null) {
            if (mOpenVPNThread != null)
                ((OpenVPNThread) mOpenVPNThread).setReplaceConnection();
            if (mManagement.stopVPN(true)) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    //ignore
                }
            }
        }

        forceStopOpenVpnProcess();
    }

    public void forceStopOpenVpnProcess() {
        synchronized (mProcessLock) {
            if (mProcessThread != null) {
                mProcessThread.interrupt();
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    //ignore
                }
            }
        }
    }

    private OpenVPNManagement instantiateOpenVPN3Core() {
        try {
            Class cl = Class.forName("de.blinkt.openvpn.core.OpenVPNThreadv3");
            return (OpenVPNManagement) cl.getConstructor(OpenVPNService.class, VpnProfile.class).newInstance(this, mProfile);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
            // Ignore exception for receiver not registered
        }
        VpnStatus.removeStateListener(this);
        VpnStatus.flushLog();
    }

    public ParcelFileDescriptor openTun() {
        Builder builder = new Builder();

        VpnStatus.logInfo(R.string.last_openvpn_tun_config);

        if (mLocalIP == null && mLocalIPv6 == null) {
            VpnStatus.logError(getString(R.string.opentun_no_ipaddr));
            return null;
        }

        if (mLocalIP != null) {
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

        IpAddress multicastRange = new IpAddress(new CIDRIP("224.0.0.0", 3), true);

        for (IpAddress route : positiveIPv4Routes) {
            try {
                if (!multicastRange.containsNet(route))
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

        mLastTunCfg = getTunConfigString();

        mDnslist.clear();
        mRoutes.clear();
        mRoutesv6.clear();
        mLocalIP = null;
        mLocalIPv6 = null;
        mDomain = null;

        try {
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

    @Override
    public void updateState(String state, String logmessage, int resid, ConnectionStatus level, Intent intent) {
        doSendBroadcast(state, level);
    }

    @Override
    public void setConnectedVPN(String uuid) {
    }

    private void doSendBroadcast(String state, ConnectionStatus level) {
        Intent vpnstatus = new Intent();
        vpnstatus.setAction("de.blinkt.openvpn.VPN_STATUS");
        vpnstatus.putExtra("status", level.toString());
        vpnstatus.putExtra("detailstatus", state);
        sendBroadcast(vpnstatus, android.Manifest.permission.ACCESS_NETWORK_STATE);
        sendMessage(state);
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
                return "OPEN_AFTER_CLOSE";
            else
                return "OPEN_BEFORE_CLOSE";
        }
    }

    public void requestInputFromUser(int resid, String needed) {
        VpnStatus.updateStateString("NEED", "need " + needed, resid, ConnectionStatus.LEVEL_WAITING_FOR_USER_INPUT);
    }

    private void sendMessage(String state) {
        Intent intent = new Intent("connectionState");
        intent.putExtra("state", state);
        OpenVPNService.state = state;
        LocalBroadcastManager.getInstance(getApplicationContext()).sendBroadcast(intent);
    }

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
            return OpenVPNService.this;
        }
    }

    public static String getStatus() {
        return state;
    }

    public static void setDefaultStatus() {
        state = "idle";
    }

    public boolean isConnected() {
        return flag;
    }
}
