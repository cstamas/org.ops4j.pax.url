/*
 * Copyright 2007 Alin Dreghiciu.
 * Copyright (C) 2014 Guillaume Nodet
 *
 * Licensed  under the  Apache License,  Version 2.0  (the "License");
 * you may not use  this file  except in  compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed  under the  License is distributed on an "AS IS" BASIS,
 * WITHOUT  WARRANTIES OR CONDITIONS  OF ANY KIND, either  express  or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ops4j.pax.url.mvn.internal.config;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import eu.maveniverse.maven.mima.context.ContextOverrides;
import org.codehaus.plexus.util.FileUtils;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.ops4j.lang.NullArgumentException;
import org.ops4j.pax.url.mvn.ServiceConstants;
import org.ops4j.pax.url.mvn.internal.AetherBasedResolver;
import org.ops4j.util.property.PropertyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.stream.Collectors.toList;

/**
 * Service Configuration implementation.
 * 
 * @author Alin Dreghiciu
 * @author Guillaume Nodet
 * @see MavenConfiguration
 * @since August 11, 2007
 */
public class MavenConfigurationImpl implements MavenConfiguration {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(MavenConfigurationImpl.class);

    /**
     * The character that should be the first character in repositories property in order to be
     * appended with the repositories from settings.xml.
     */
    private final static String REPOSITORIES_APPEND_SIGN = "+";
    /**
     * Repositories separator.
     */
    private final static String REPOSITORIES_SEPARATOR = ",";
    private final static String REPOSITORIES_SEPARATOR_SPLIT = "\\s*,\\s*";
    /**
     * Use a default timeout of 5 seconds.
     */
    private final static String DEFAULT_TIMEOUT = "5000";

    /**
     * Configuration PID. Cannot be null or empty.
     */
    private final String m_pid;
    /**
     * Property resolver. Cannot be null.
     */
    private final PropertyResolver m_propertyResolver;

    private final ContextOverrides contextOverrides;

    /**
     * Creates a new service configuration.
     * 
     * @param propertyResolver
     *            propertyResolver used to resolve properties; mandatory
     * @param pid
     *            configuration PID; mandatory
     */
    public MavenConfigurationImpl(final PropertyResolver propertyResolver, final String pid) throws MalformedURLException {
        NullArgumentException.validateNotNull(propertyResolver, "Property resolver");

        m_pid = pid == null ? "" : pid + ".";
        m_propertyResolver = propertyResolver;

        ContextOverrides.Builder builder = ContextOverrides.Builder.create();

        builder.withUserSettings(true); // obey Maven environment (discover settings. local repo, etc)

        URL settingsFile = getSettingsFileUrl();
        if (settingsFile != null) {
            builder.settingsXml(FileUtils.toFile(settingsFile).toPath());
        }

        builder.offline(isOffline());

        String globalUpdatePolicy = getGlobalUpdatePolicy();
        if (globalUpdatePolicy != null) {
            if ( RepositoryPolicy.UPDATE_POLICY_ALWAYS.equals(globalUpdatePolicy) ) {
                builder.snapshotUpdatePolicy( ContextOverrides.SnapshotUpdatePolicy.ALWAYS );
            } else if (RepositoryPolicy.UPDATE_POLICY_NEVER.equals( globalUpdatePolicy )) {
                builder.snapshotUpdatePolicy( ContextOverrides.SnapshotUpdatePolicy.NEVER );
            } else {
                throw new IllegalArgumentException("Unsupported update policy: " + globalUpdatePolicy);
            }
        }
        String globalChecksumPolicy = getGlobalChecksumPolicy();
        if (globalChecksumPolicy != null) {
            if (RepositoryPolicy.CHECKSUM_POLICY_IGNORE.equals(globalChecksumPolicy)) {
                builder.checksumPolicy( ContextOverrides.ChecksumPolicy.IGNORE);
            } else if (RepositoryPolicy.CHECKSUM_POLICY_WARN.equals(globalChecksumPolicy)) {
                builder.checksumPolicy( ContextOverrides.ChecksumPolicy.WARN );
            } else if (RepositoryPolicy.CHECKSUM_POLICY_FAIL.equals(globalChecksumPolicy)) {
                builder.checksumPolicy( ContextOverrides.ChecksumPolicy.FAIL );
            } else {
                throw new IllegalArgumentException("Unsupported checksum policy: " + globalChecksumPolicy);
            }
        }

        Boolean certificateCheck = getCertificateCheck();
        if (certificateCheck != null && certificateCheck) {
            builder.setConfigProperty("aether.connector.https.securityMode", "insecure");
        }

        MavenRepositoryURL localRepo = getLocalRepository();
        if (localRepo != null) {
            builder.localRepository(localRepo.getFile().toPath()); // overrides user env (but only local repo)
        }

        if (m_propertyResolver.get(m_pid + ServiceConstants.PROPERTY_REPOSITORIES).contains(REPOSITORIES_APPEND_SIGN)) {
            builder.appendRepositories(true);
        }

        List<RemoteRepository> remoteRepositories = new ArrayList<>();
        List<MavenRepositoryURL> defaultRepositories = getDefaultRepositories();
        List<MavenRepositoryURL> repositories = getRepositories();
        if (defaultRepositories != null && !defaultRepositories.isEmpty()) {
            remoteRepositories.addAll(defaultRepositories.stream()
                    .map(AetherBasedResolver::toRemoteRepository)
                    .collect(toList()));
        }
        if (repositories != null && !repositories.isEmpty()) {
            remoteRepositories.addAll(repositories.stream()
                    .map(AetherBasedResolver::toRemoteRepository)
                    .collect(toList()));
        }
        if (!remoteRepositories.isEmpty()) {
            builder.repositories(remoteRepositories);
        }

        contextOverrides = builder.build();
    }

    @Override
    public PropertyResolver getPropertyResolver() {
        return m_propertyResolver;
    }

    @Override
    public ContextOverrides contextOverrides() {
        return contextOverrides;
    }

    public boolean isValid() {
        return m_propertyResolver.get(m_pid + ServiceConstants.REQUIRE_CONFIG_ADMIN_CONFIG) == null;
    }

    /**
     * @see MavenConfiguration#isOffline()
     */
    public boolean isOffline() {
        if (!contains(m_pid + ServiceConstants.PROPERTY_OFFLINE)) {
            return set(
                    m_pid + ServiceConstants.PROPERTY_OFFLINE,
                    Boolean.valueOf(m_propertyResolver.get(m_pid
                            + ServiceConstants.PROPERTY_OFFLINE)));
        }
        return get(m_pid + ServiceConstants.PROPERTY_OFFLINE);
    }

    /**
     * @see MavenConfiguration#getCertificateCheck()
     */
    public Boolean getCertificateCheck() {
        if (!contains(m_pid + ServiceConstants.PROPERTY_CERTIFICATE_CHECK)) {
            return set(
                m_pid + ServiceConstants.PROPERTY_CERTIFICATE_CHECK,
                Boolean.valueOf(m_propertyResolver.get(m_pid
                    + ServiceConstants.PROPERTY_CERTIFICATE_CHECK)));
        }
        return get(m_pid + ServiceConstants.PROPERTY_CERTIFICATE_CHECK);
    }

    public URL getSettingsFileUrl()
    {
        if ( !contains( m_pid + ServiceConstants.PROPERTY_SETTINGS_FILE ) )
        {
            String spec = m_propertyResolver.get( m_pid + ServiceConstants.PROPERTY_SETTINGS_FILE );
            if ( spec == null )
            {
                spec = safeGetFile( System.getProperty( "user.home" ) + "/.m2/settings.xml" );
            }
            if ( spec == null )
            {
                spec = safeGetFile( System.getProperty( "maven.home" ) + "/conf/settings.xml" );
            }
            if ( spec == null )
            {
                spec = safeGetFile( System.getenv( "M2_HOME" ) + "/conf/settings.xml" );
            }
            if ( spec != null )
            {
                try
                {
                    return set( m_pid + ServiceConstants.PROPERTY_SETTINGS_FILE, new URL( spec ) );
                }
                catch ( MalformedURLException e )
                {
                    File file = new File( spec );
                    if ( file.exists() )
                    {
                        try
                        {
                            return set( m_pid + ServiceConstants.PROPERTY_SETTINGS_FILE, file.toURI()
                                    .toURL() );
                        }
                        catch ( MalformedURLException ignore )
                        {
                            // ignore as it usually should not happen since we already have a file
                        }
                    }
                    else
                    {
                        LOGGER
                                .warn( "Settings file ["
                                        + spec
                                        + "] cannot be used and will be skipped (malformed url or file does not exist)" );
                        set( m_pid + ServiceConstants.PROPERTY_SETTINGS_FILE, null );
                    }
                }
            }
        }
        return get( m_pid + ServiceConstants.PROPERTY_SETTINGS_FILE );
    }

    private String safeGetFile(String path) {
        if (path != null) {
            File file = new File(path);
            if (file.exists() && file.canRead() && file.isFile()) {
                try {
                    return file.toURI().toURL().toExternalForm();
                } catch (MalformedURLException e) {
                    // Ignore
                }
            }
        }
        return null;
    }

    /**
     * Repository is a comma separated list of repositories to be used. If repository acces requests
     * authentication the user name and password must be specified in the repository url as for
     * example http://user:password@repository.ops4j.org/maven2.<br/>
     * If the repository from 1/2 bellow starts with a plus (+) the option 3 is also used and the
     * repositories from settings.xml will be cummulated.<br/>
     * Repository resolution:<br/>
     * 1. looks for a configuration property named repository;<br/>
     * 2. looks for a framework property/system setting repository;<br/>
     * repositories will be used including configured user/password. In this case the central
     * repository is also added. Note that the local repository is added as the first repository if
     * exists.
     * 
     * @see MavenConfiguration#getRepositories()
     * @see MavenConfiguration#getLocalRepository()
     */
    public List<MavenRepositoryURL> getDefaultRepositories() throws MalformedURLException {
        if (!contains(m_pid + ServiceConstants.PROPERTY_DEFAULT_REPOSITORIES)) {
            // look for repositories property
            String defaultRepositoriesProp = m_propertyResolver.get(m_pid
                + ServiceConstants.PROPERTY_DEFAULT_REPOSITORIES);
            // build repositories list
            final List<MavenRepositoryURL> defaultRepositoriesProperty = new ArrayList<>();
            if (defaultRepositoriesProp != null && defaultRepositoriesProp.trim().length() > 0) {
                String[] repositories = defaultRepositoriesProp.split(REPOSITORIES_SEPARATOR_SPLIT);
                for (String repositoryURL : repositories) {
                    defaultRepositoriesProperty.add(new MavenRepositoryURL(repositoryURL.trim()));
                }
            }
            LOGGER.trace("Using default repositories [" + defaultRepositoriesProperty + "]");
            return set(m_pid + ServiceConstants.PROPERTY_DEFAULT_REPOSITORIES,
                defaultRepositoriesProperty);
        }
        return get(m_pid + ServiceConstants.PROPERTY_DEFAULT_REPOSITORIES);
    }

    /**
     * Repository is a comma separated list of repositories to be used. If repository access requests
     * authentication the user name and password must be specified in the repository url as for
     * example http://user:password@repository.ops4j.org/maven2.<br/>
     * If the repository from 1/2 bellow starts with a plus (+) the option 3 is also used and the
     * repositories from settings.xml will be cummulated.<br/>
     * Repository resolution:<br/>
     * 1. looks for a configuration property named repository;<br/>
     * 2. looks for a framework property/system setting repository;<br/>
     *
     * @see MavenConfiguration#getRepositories()
     * @see MavenConfiguration#getLocalRepository()
     */
    public List<MavenRepositoryURL> getRepositories() throws MalformedURLException {
        if (!contains(m_pid + ServiceConstants.PROPERTY_REPOSITORIES)) {
            // look for repositories property
            String repositoriesProp = m_propertyResolver.get(m_pid
                + ServiceConstants.PROPERTY_REPOSITORIES);
            final List<MavenRepositoryURL> repositoriesProperty = new ArrayList<>();
            if (repositoriesProp != null && repositoriesProp.trim().length() > 0) {
                String[] repositories = repositoriesProp.split(REPOSITORIES_SEPARATOR_SPLIT);
                for (String repositoryURL : repositories) {
                    if (!"".equals(repositoryURL.trim())) {
                        repositoriesProperty.add(new MavenRepositoryURL(repositoryURL.trim()));
                    }
                }
            }
            LOGGER.trace("Using remote repositories [" + repositoriesProperty + "]");
            return set(m_pid + ServiceConstants.PROPERTY_REPOSITORIES, repositoriesProperty);
        }
        return get(m_pid + ServiceConstants.PROPERTY_REPOSITORIES);
    }

    public String getGlobalUpdatePolicy() {
        final String propertyName = m_pid + ServiceConstants.PROPERTY_GLOBAL_UPDATE_POLICY;
        if (contains(propertyName)) {
            return get(propertyName);
        }
        final String propertyValue = m_propertyResolver.get(propertyName);
        if (propertyValue != null) {
            set(propertyName, propertyValue);
            return propertyValue;
        }
        return null;
    }

    public String getGlobalChecksumPolicy() {
        final String propertyName = m_pid + ServiceConstants.PROPERTY_GLOBAL_CHECKSUM_POLICY;
        if (contains(propertyName)) {
            return get(propertyName);
        }
        final String propertyValue = m_propertyResolver.get(propertyName);
        if (propertyValue != null) {
            set(propertyName, propertyValue);
            return propertyValue;
        }
        return null;
    }

    /**
     * Resolves local repository directory by using the following resolution:<br/>
     * 1. looks for a configuration property named {@code localRepository};<br/>
     * 2. looks for a framework property/system setting localRepository;<br/>
     * otherwise returns null.
     *
     * @see MavenConfiguration#getLocalRepository()
     */
    public MavenRepositoryURL getLocalRepository() {
        if (!contains(m_pid + ServiceConstants.PROPERTY_LOCAL_REPOSITORY)) {
            // look for a local repository property
            String spec = m_propertyResolver.get(m_pid + ServiceConstants.PROPERTY_LOCAL_REPOSITORY);
            if (spec != null) {
                try {
                    return set(m_pid + ServiceConstants.PROPERTY_LOCAL_REPOSITORY,
                            new MavenRepositoryURL(spec));
                }
                catch (MalformedURLException e) {
                    // maybe is just a file?
                    try {
                        return set(m_pid + ServiceConstants.PROPERTY_LOCAL_REPOSITORY,
                                new MavenRepositoryURL(new File(spec).toURI().toASCIIString()));
                    }
                    catch (MalformedURLException ignore) {
                        LOGGER.warn("Local repository [" + spec
                                + "] cannot be used and will be skipped");
                        return set(m_pid + ServiceConstants.PROPERTY_LOCAL_REPOSITORY, null);
                    }
                }
            }
        }
        return get(m_pid + ServiceConstants.PROPERTY_LOCAL_REPOSITORY);
    }

    public Integer getTimeout() {
        if (!contains(m_pid + ServiceConstants.PROPERTY_TIMEOUT)) {
            String timeout = m_propertyResolver.get(m_pid + ServiceConstants.PROPERTY_TIMEOUT);
            return set(m_pid + ServiceConstants.PROPERTY_TIMEOUT,
                Integer.valueOf(timeout == null ? DEFAULT_TIMEOUT : timeout));
        }
        return get(m_pid + ServiceConstants.PROPERTY_TIMEOUT);
    }

    /**
     * {@inheritDoc}
     */
    public Boolean useFallbackRepositories() {
        if (!contains(m_pid + ServiceConstants.PROPERTY_USE_FALLBACK_REPOSITORIES)) {
            String useFallbackRepoProp = m_propertyResolver.get(m_pid
                + ServiceConstants.PROPERTY_USE_FALLBACK_REPOSITORIES);
            return set(m_pid + ServiceConstants.PROPERTY_USE_FALLBACK_REPOSITORIES,
                Boolean.valueOf(useFallbackRepoProp == null ? "true" : useFallbackRepoProp));
        }
        return get(m_pid + ServiceConstants.PROPERTY_USE_FALLBACK_REPOSITORIES);
    }

    @Override
    public <T> T getProperty(String name, T defaultValue, Class<T> clazz) {
        if (!contains(m_pid + name)) {
            String value = m_propertyResolver.get(m_pid + name);
            return set(m_pid + name, value == null ? defaultValue : convert(value, clazz));
        }
        return get(m_pid + name);
    }

    @Override
    public String getPid() {
        return m_pid;
    }

    /**
     * Supports String to [ Integer, Long, String, Boolean ] conversion
     * @param value
     * @param clazz
     * @param <T>
     * @return
     */
    @SuppressWarnings("unchecked")
    private <T> T convert(String value, Class<T> clazz) {
        if (String.class == clazz) {
            return (T) value;
        }
        if (Integer.class == clazz) {
            return (T) Integer.valueOf(value);
        }
        if (Long.class == clazz) {
            return (T) Long.valueOf(value);
        }
        if (Boolean.class == clazz) {
            return (T) Boolean.valueOf("true".equals(value));
        }
        throw new IllegalArgumentException("Can't convert \"" + value + "\" to " + clazz + ".");
    }

    /**
     * Map of properties.
     */
    private final Map<String, Object> m_properties = new ConcurrentHashMap<>();

    private static final Object NULL_VALUE = new Object();

    /**
     * Returns true if the the property was set.
     *
     * @param propertyName name of the property
     *
     * @return true if property is set
     */
    public boolean contains( final String propertyName )
    {
        return m_properties.containsKey( propertyName );
    }

    /**
     * Sets a property.
     *
     * @param propertyName  name of the property to set
     * @param propertyValue value of the property to set
     *
     * @return the value of property set (fluent api)
     */
    public <T> T set( final String propertyName, final T propertyValue )
    {
        m_properties.put( propertyName, propertyValue != null ? propertyValue : NULL_VALUE );
        return propertyValue;
    }

    /**
     * Returns the property by name.
     *
     * @param propertyName name of the property
     *
     * @return property value
     */
    @SuppressWarnings( "unchecked" )
    public <T> T get( final String propertyName )
    {
        Object v = m_properties.get( propertyName );
        return v != NULL_VALUE ? (T) v : null;
    }

}
