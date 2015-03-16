# PasswordVaultUsersRolesLoginModule
A JAAS login module that uses the JBoss password vault for the passwords.  This version is specifically for JBoss EAP 6.1.0.

To use, add the JAR as a module in JBoss EAP 6.1.0.

1. For the path, use something like <b>$JBOSS_HOME/modules/system/add-ons/org/jboss/security/jaas/PasswordVaultUsersRolesLoginModule/main</b>
2. Use the following for the <b>module.xml</b> file.
```
<?xml version="1.0" encoding="UTF-8"?>
<module xmlns="urn:jboss:module:1.1" name="org.jboss.security.jaas">
    <resources>
        <resource-root path="PasswordVaultUsersRolesLoginModule-0.0.1-SNAPSHOT.jar"/>
    </resources>
    <dependencies>
        <module name="javax.api"/>
        <module name="org.jboss.logging"/>
        <module name="org.jboss.modules"/>
        <module name="org.picketbox"/>
    </dependencies>
</module>
```
In the JBoss EAP configuration file, first add a global module in the ee subsystem like so:

```
        <subsystem xmlns="urn:jboss:domain:ee:1.1">
            <global-modules>
                <module name="org.jboss.security.jaas" slot="main"/>
            </global-modules>
            ...
```

In the same configuration file, add a security-domain in the security subsystem, something like:

```
                <security-domain name="MySecurityDomain" cache-type="default">
                    <authentication>
                        <login-module code="org.jboss.security.jaas.PasswordVaultUsersRolesLoginModule" flag="required">
                            <module-option name="usersProperties" value="${jboss.server.config.dir}/props/test-users.properties"/>
                            <module-option name="rolesProperties" value="${jboss.server.config.dir}/props/test-roles.properties"/>
                            <module-option name="KEYSTORE_URL" value="$PATH_TO_KEYSTORE"/>
                            <module-option name="KEYSTORE_ALIAS" value="$VAULT"/>
                            <module-option name="KEYSTORE_PASSWORD" value="$MASKED_PASSWORD"/>
                            <module-option name="SALT" value="$SALT"/>
                            <module-option name="ITERATION_COUNT" value="$ITERATION_COUNT"/>
                            <module-option name="ENC_FILE_DIR" value="$ENCRYPTION_FILE_DIRECTORY"/>
                        </login-module>
                    </authentication>
                </security-domain>
```
See https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Application_Platform/6.1/html-single/Administration_and_Configuration_Guide/#sect-Password_Vaults_for_Sensitive_Strings on how to create a password vault.


