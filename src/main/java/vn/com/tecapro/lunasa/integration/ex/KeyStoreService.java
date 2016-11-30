package vn.com.tecapro.lunasa.integration.ex;

import com.safenetinc.luna.LunaSlotManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Created by HoangTD on 11/29/2016.
 */
public class KeyStoreService {
    private static KeyStoreService instance = new KeyStoreService();

    private static final Logger log = LoggerFactory.getLogger(KeyStoreService.class);

    private LunaSlotManager hsmConnection;

    private KeyStoreService() {
    }

    public static KeyStoreService getInstance() {
        return instance;
    }

    private void resolveLunaSlotManagerInstance() throws Exception {
        if (hsmConnection == null) {
            hsmConnection = LunaSlotManager.getInstance();
        }
        if (hsmConnection == null) {
            log.error("LunaSlotManager did not return an instance.");
            throw new Exception("LunaSlotManager did not return an instance.");
        }
    }

    private void hsmConnectionLogin(String hsmTokenLabel, String hsmTokenPassword) {
        synchronized (hsmConnection) {
            if (!hsmConnection.isLoggedIn()) {
                hsmConnection.login(hsmTokenLabel, hsmTokenPassword);
            }
        }
    }

    void refreshHsmConnection(String hsmTokenLabel, String hsmTokenPassword) throws Exception {
        try {
            resolveLunaSlotManagerInstance();
            hsmConnectionLogin(hsmTokenLabel, hsmTokenPassword);
        } catch (Throwable t) {
            log.error("Unable to login to the Hardware Storage Module (HSM). E-signing can't be completed without access to a certificate");
            throw new Exception("Unable to login to the Hardware Storage Module (HSM). E-signing can't be completed without access to a certificate");
        }
    }

    public Map load() throws Exception {
        //load properties
        String resourceName = "config.properties";
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties props = new Properties();
        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        props.load(resourceStream);


        //dynamicly inject provider
        java.security.Provider provider = new com.safenetinc.luna.provider.LunaProvider();
        java.security.Security.removeProvider(provider.getName());
        java.security.Security.insertProviderAt(provider, 2);

        String hsmTokenLabel = props.getProperty("hsmTokenLabel");
        String hsmTokenPassword = props.getProperty("hsmTokenPassword");
        String hsmKeyLabel = props.getProperty("hsmKeyLabel");
        String userCertLabel = props.getProperty("userCertLabel");
        String subCertLabel = props.getProperty("subCertLabel");
        String rootCertLabel = props.getProperty("rootCertLabel");

        refreshHsmConnection(hsmTokenLabel, hsmTokenPassword);
        KeyStore ks = KeyStore.getInstance("Luna");
        ks.load(null, null);

        PrivateKey privKey = (PrivateKey) ks.getKey(hsmKeyLabel, null);
        Map credentials = new HashMap();
        credentials.put("privateKey", privKey);

        Certificate[] chain = new Certificate[3];
        chain[0] = ks.getCertificate(userCertLabel);
        chain[1] = ks.getCertificate(subCertLabel);
        chain[2] = ks.getCertificate(rootCertLabel);

        credentials.put("chain", chain);

        return credentials;
    }

    public static void main(String[] args) {
        try {
            KeyStoreService kss = KeyStoreService.getInstance();
            kss.load();
        } catch (Exception e) {
            log.error(e.getMessage());
            e.printStackTrace();
        }
    }
}
