package org.jboss.security.jaas;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.jboss.logging.Logger;
import org.jboss.security.auth.spi.UsersRolesLoginModule;
import org.jboss.security.util.StringPropertyReplacer;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.jboss.security.vault.SecurityVaultFactory;
import org.picketbox.plugins.vault.PicketBoxSecurityVault;

public class PasswordVaultUsersRolesLoginModule extends UsersRolesLoginModule {
    private static final Logger LOGGER = Logger.getLogger(PasswordVaultUsersRolesLoginModule.class);
    private static final Pattern SECRET_PATTERN = Pattern.compile("VAULT::([^\\s]+)::([^\\s]+)::([^\\s]+)");
    private static final String KEYSTORE_URL = "KEYSTORE_URL";
    private static final String KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";
    private static final String KEYSTORE_ALIAS = "KEYSTORE_ALIAS";
    private static final String SALT = "SALT";
    private static final String ITERATION_COUNT = "ITERATION_COUNT";
    private static final String ENC_FILE_DIR = "ENC_FILE_DIR";

    private String keystoreUrl = "";
    private String keystorePassword = "";
    private String keystoreAlias = "";
    private String salt = "";
    private String iterationCount = "";
    private String encFileDir = "";

    @Override
    protected String getUsersPassword() {
        String encryptedPassword = super.getUsersPassword();
        Matcher matcher = null;
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Encrypted password = " + encryptedPassword);
        }
        if (encryptedPassword != null) {
            matcher = SECRET_PATTERN.matcher(encryptedPassword);
            if (!matcher.matches()) {
                LOGGER.error("Invalid password pattern");
            }
            else {
                try {
                    SecurityVault vault = initVault();
                    String block = matcher.group(1);
                    String attribute = matcher.group(2);
                    String sharedKey = matcher.group(3);
                    String password = new String(vault.retrieve(block, attribute, sharedKey.getBytes()));
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Password = " + password);
                    }
                    return password;
                }
                catch (Exception e) {
                    LOGGER.error(e);
                }
            }
        }
        return "";
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        keystoreUrl = getProperty(options, KEYSTORE_URL);
        keystorePassword = getProperty(options, KEYSTORE_PASSWORD);
        keystoreAlias = getProperty(options, KEYSTORE_ALIAS);
        salt = getProperty(options, SALT);
        iterationCount = getProperty(options, ITERATION_COUNT);
        encFileDir = getProperty(options, ENC_FILE_DIR);

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Login module initialize called");
            LOGGER.info("KEYSTORE_URL = " + keystoreUrl);
            LOGGER.info("KEYSTORE_PASSWORD = " + keystorePassword);
            LOGGER.info("KEYSTORE_ALIAS = " + keystoreAlias);
            LOGGER.info("SALT = " + salt);
            LOGGER.info("ITERATION_COUNT = " + iterationCount);
            LOGGER.info("ENC_FILE_DIR = " + encFileDir);
        }
    }

    private SecurityVault initVault() throws Exception {
        SecurityVault vault = SecurityVaultFactory.get();
        if (areVaultPropertiesDefined()) {
            // vault params are defined so we use this vault
            Map<String, Object> options = new HashMap<>();
            options.put(PicketBoxSecurityVault.ENC_FILE_DIR, encFileDir);
            options.put(PicketBoxSecurityVault.KEYSTORE_URL, keystoreUrl);
            options.put(PicketBoxSecurityVault.KEYSTORE_ALIAS, keystoreAlias);
            options.put(PicketBoxSecurityVault.ITERATION_COUNT, iterationCount);
            options.put(PicketBoxSecurityVault.SALT, salt);
            options.put(PicketBoxSecurityVault.KEYSTORE_PASSWORD, keystorePassword);
            vault.init(options);

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Password Vault initialized");
            }
        }
        else if (vault != null && vault.isInitialized()) {
            // vault is already initialized
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Security vault is already initialized");
            }
        }
        else {
            throw new SecurityVaultException(
                    "No instance of vault can be found.  Either define a <vault> section in the configuration or define <module-option> for all vault properties in the login module");
        }

        return vault;
    }

    private boolean areVaultPropertiesDefined() {
        return !isEmptyString(encFileDir) && !isEmptyString(iterationCount) && !isEmptyString(keystoreAlias) && !isEmptyString(keystorePassword)
                && !isEmptyString(keystoreUrl) && !isEmptyString(salt);
    }

    private String getProperty(Map<String, ?> options, String property) {
        String option = (String) options.get(property);
        if (!isEmptyString(option)) {
            return StringPropertyReplacer.replaceProperties(option);
        }
        return "";
    }

    private static boolean isEmptyString(String string) {
        return string == null || string.trim().equals("");
    }
}
