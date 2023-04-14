/*
 * Copyright (C) 2010 Toni Menzel
 * Copyright (C) 2014 Guillaume Nodet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ops4j.pax.url.mvn.internal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import eu.maveniverse.maven.mima.context.Context;
import eu.maveniverse.maven.mima.context.ContextOverrides;
import eu.maveniverse.maven.mima.context.Runtimes;
import org.apache.maven.artifact.repository.metadata.SnapshotVersion;
import org.apache.maven.artifact.repository.metadata.Versioning;
import org.apache.maven.artifact.repository.metadata.io.xpp3.MetadataXpp3Reader;
import org.apache.maven.artifact.repository.metadata.io.xpp3.MetadataXpp3Writer;
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.installation.InstallRequest;
import org.eclipse.aether.metadata.DefaultMetadata;
import org.eclipse.aether.metadata.Metadata;
import org.eclipse.aether.repository.LocalMetadataRequest;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.resolution.MetadataRequest;
import org.eclipse.aether.resolution.MetadataResult;
import org.eclipse.aether.resolution.VersionRangeRequest;
import org.eclipse.aether.resolution.VersionRangeResolutionException;
import org.eclipse.aether.resolution.VersionRangeResult;
import org.eclipse.aether.transfer.ArtifactNotFoundException;
import org.eclipse.aether.transfer.ArtifactTransferException;
import org.eclipse.aether.transfer.MetadataNotFoundException;
import org.eclipse.aether.transfer.MetadataTransferException;
import org.eclipse.aether.util.version.GenericVersionScheme;
import org.eclipse.aether.version.InvalidVersionSpecificationException;
import org.eclipse.aether.version.Version;
import org.eclipse.aether.version.VersionConstraint;
import org.ops4j.lang.NullArgumentException;
import org.ops4j.pax.url.mvn.MavenResolver;
import org.ops4j.pax.url.mvn.ServiceConstants;
import org.ops4j.pax.url.mvn.internal.config.MavenConfiguration;
import org.ops4j.pax.url.mvn.internal.config.MavenRepositoryURL;
import org.slf4j.LoggerFactory;

import static org.eclipse.aether.repository.RepositoryPolicy.CHECKSUM_POLICY_WARN;
import static org.eclipse.aether.repository.RepositoryPolicy.UPDATE_POLICY_DAILY;
import static org.ops4j.pax.url.mvn.internal.Parser.VERSION_LATEST;

/**
 * Aether based, drop in replacement for mvn protocol
 */
public class AetherBasedResolver implements MavenResolver {

    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(AetherBasedResolver.class);
    private static final String LATEST_VERSION_RANGE = "[0.0,)";
    private static final String REPO_TYPE = "default";
    private static final String RESOLVER_CONTEXT = ServiceConstants.PID;

    final private Context m_context;

    /**
     * Create a AetherBasedResolver
     *
     * @param configuration (must be not null)
     */
    public AetherBasedResolver(final MavenConfiguration configuration) {
        NullArgumentException.validateNotNull(configuration, "Maven configuration");
        m_context = Runtimes.INSTANCE.getRuntime().create(configuration.contextOverrides());
    }

    @Override
    public void close() throws IOException {
        m_context.close();
    }

    public RepositorySystem getRepositorySystem() {
        return m_context.repositorySystem();
    }

    public List<RemoteRepository> getRepositories() {
        return m_context.remoteRepositories();
    }

    @Override
    public File resolve(String url) throws IOException {
        return resolve(url, null);
    }

    @Override
    public File resolve(String url, Exception previousException) throws IOException {
        if (!url.startsWith(ServiceConstants.PROTOCOL + ":")) {
            throw new IllegalArgumentException("url should be a mvn based url");
        }
        url = url.substring((ServiceConstants.PROTOCOL + ":").length());
        Parser parser = new Parser(url);
        return resolve(
                parser.getGroup(),
                parser.getArtifact(),
                parser.getClassifier(),
                parser.getType(),
                parser.getVersion(),
                parser.getRepositoryURL(),
                previousException
        );
    }

    /**
     * Resolve maven artifact as file in repository.
     */
    @Override
    public File resolve(String groupId, String artifactId, String classifier,
                        String extension, String version) throws IOException {
        return resolve(groupId, artifactId, classifier, extension, version, null, null);
    }

    @Override
    public File resolve(String groupId, String artifactId, String classifier, String extension, String version, Exception previousException) throws IOException {
        return resolve(groupId, artifactId, classifier, extension, version, null, previousException);
    }

    /**
     * Resolve maven artifact as file in repository.
     */
    public File resolve(String groupId, String artifactId, String classifier,
                        String extension, String version,
                        MavenRepositoryURL repositoryURL,
                        Exception previousException) throws IOException {
        Artifact artifact = new DefaultArtifact(groupId, artifactId, classifier, extension, version);
        return resolve(artifact, repositoryURL, previousException);
    }

    /**
     * Resolve maven artifact as file in repository.
     */
    public File resolve(Artifact artifact) throws IOException {
        return resolve(artifact, null, null);
    }

    /**
     * Resolve maven artifact as file in repository.
     */
    public File resolve(Artifact artifact,
                        MavenRepositoryURL repositoryURL,
                        Exception previousException) throws IOException {

        List<RemoteRepository> remoteRepos = m_context.remoteRepositories();
        if (repositoryURL != null) {
            remoteRepos.add(0, toRemoteRepository(repositoryURL));
            remoteRepos = m_context.repositorySystem()
                    .newResolutionRepositories(m_context.repositorySystemSession(), remoteRepos);
        }

        // PAXURL-337: use previousException as hint to alter remote repositories to query
        if (previousException != null) {
            // we'll try using previous repositories, without these that will fail again anyway
            List<RemoteRepository> altered = new LinkedList<>();
            RepositoryException repositoryException = findAetherException(previousException);
            if (repositoryException instanceof ArtifactResolutionException) {
                // check only this aggregate exception and assume it's related to current artifact
                ArtifactResult result = ((ArtifactResolutionException) repositoryException).getResult();
                if (result != null && result.getRequest() != null && result.getRequest().getArtifact().equals(artifact)) {
                    // one exception per repository checked
                    // consider only ArtifactTransferException:
                    //  - they may be recoverable
                    //  - these exceptions contain repository that was checked
                    for (Exception exception : result.getExceptions()) {
                        RepositoryException singleException = findAetherException(exception);
                        if (singleException instanceof ArtifactTransferException) {
                            RemoteRepository repository = ((ArtifactTransferException) singleException).getRepository();
                            if (repository != null) {
                                RetryChance chance = isRetryableException(singleException);
                                if (chance == RetryChance.NEVER) {
                                    LOG.debug("Removing " + repository + " from list of repositories, previous exception: " +
                                            singleException.getClass().getName() + ": " + singleException.getMessage());
                                } else {
                                    altered.add(repository);
                                }
                            }
                        }
                    }

                    // swap list of repos now
                    remoteRepos = altered;
                }
            }
        }

        File resolved = resolve(remoteRepos, artifact);

        LOG.debug("Resolved ({}) as {}", artifact, resolved.getAbsolutePath());
        return resolved;
    }

    private File resolve(List<RemoteRepository> remoteRepos,
                         Artifact artifact) throws IOException {
        if (artifact.getExtension().isEmpty()) {
            artifact = new DefaultArtifact(
                    artifact.getGroupId(),
                    artifact.getArtifactId(),
                    artifact.getClassifier(),
                    "jar",
                    artifact.getVersion()
            );
        }

        if (artifact.getVersion().equals(VERSION_LATEST)) {
            artifact = artifact.setVersion(LATEST_VERSION_RANGE);
        }

        try (Context ctx = m_context.customize(ContextOverrides.Builder.create().repositories(remoteRepos).build()))
        {
            RepositorySystem repositorySystem = ctx.repositorySystem();
            RepositorySystemSession session = ctx.repositorySystemSession();

            try
            {
                GenericVersionScheme genericVersionScheme = new GenericVersionScheme();
                VersionConstraint vc = genericVersionScheme.parseVersionConstraint( artifact.getVersion() );

                if ( vc.getVersion() == null && vc.getRange() != null )
                {
                    // KARAF-6005: try to resolve version range against local repository (default repository)
                    Metadata metadata =
                            new DefaultMetadata( artifact.getGroupId(), artifact.getArtifactId(),
                                    "maven-metadata.xml", Metadata.Nature.RELEASE_OR_SNAPSHOT );
                    new LocalMetadataRequest( metadata, null, RESOLVER_CONTEXT );

                    LocalRepositoryManager lrm = session.getLocalRepositoryManager();
                    String path = lrm.getPathForLocalMetadata( metadata );
                    File metadataLocation = new File( lrm.getRepository().getBasedir(), path ).getParentFile();

                    Set<Version> versions = new TreeSet<>();
                    if ( metadataLocation.isDirectory() )
                    {
                        if ( !new File( metadataLocation, "maven-metadata.xml" ).isFile() )
                        {
                            // we will generate (kind of) maven-metadata.xml manually
                            String[] versionDirs = metadataLocation.list();
                            if ( versionDirs != null )
                            {
                                for ( String vd : versionDirs )
                                {
                                    Version ver = genericVersionScheme.parseVersion( vd );
                                    if ( vc.containsVersion( ver ) )
                                    {
                                        versions.add( ver );
                                    }
                                }
                            }
                            VersionRangeResult vrr = new VersionRangeResult( new VersionRangeRequest() );
                            vrr.setVersions( new LinkedList<>( versions ) );

                            if ( vrr.getHighestVersion() != null )
                            {
                                if ( LOG.isDebugEnabled() )
                                {
                                    LOG.debug( "Resolved version range {} as {}", vc.getRange(),
                                            vrr.getHighestVersion().toString() );
                                }
                                vc = new GenericVersionScheme().parseVersionConstraint(
                                        vrr.getHighestVersion().toString() );
                                artifact = artifact.setVersion( vc.getVersion().toString() );
                            }
                        }
                        else
                        {
                            // we can use normal metadata resolution algorithm
                            try
                            {
                                VersionRangeResult versionResult = repositorySystem.resolveVersionRange( session,
                                        new VersionRangeRequest( artifact, null, RESOLVER_CONTEXT ) );
                                if ( versionResult != null )
                                {
                                    Version v = versionResult.getHighestVersion();
                                    if ( v != null )
                                    {
                                        if ( LOG.isDebugEnabled() )
                                        {
                                            LOG.debug( "Resolved version range {} as {}", vc.getRange(), v.toString() );
                                        }
                                        vc = new GenericVersionScheme().parseVersionConstraint( v.toString() );
                                        artifact = artifact.setVersion( vc.getVersion().toString() );
                                    }
                                }
                            }
                            catch ( VersionRangeResolutionException e )
                            {
                                // Ignore
                            }
                        }
                    }
                }
                if ( vc.getVersion() != null )
                {
                    // normal resolution without ranges
                    try
                    {
                        return repositorySystem
                                .resolveArtifact( session, new ArtifactRequest( artifact, null, RESOLVER_CONTEXT ) )
                                .getArtifact().getFile();
                    }
                    catch ( ArtifactResolutionException e )
                    {
                        // Ignore
                    }
                }
            }
            catch ( InvalidVersionSpecificationException e )
            {
                // Should not happen
            }
            try
            {
                artifact = resolveLatestVersionRange( ctx, remoteRepos, artifact );
                return repositorySystem
                        .resolveArtifact( session, new ArtifactRequest( artifact, remoteRepos, RESOLVER_CONTEXT ) )
                        .getArtifact().getFile();
            }
            catch ( ArtifactResolutionException e )
            {
                // we know there's one ArtifactResult, because there was one ArtifactRequest
                ArtifactResolutionException original = new ArtifactResolutionException( e.getResults(),
                        "Error resolving artifact " + artifact.toString(), null );

                throw configureIOException( original, e, e.getResult().getExceptions() );
            }
            catch ( VersionRangeResolutionException e )
            {
                // we know there's one ArtifactResult, because there was one ArtifactRequest
                VersionRangeResolutionException original = new VersionRangeResolutionException( e.getResult(),
                        "Error resolving artifact " + artifact.toString(), null );

                throw configureIOException( original, e, e.getResult().getExceptions() );
            }
        }
    }

    /**
     * Take original maven exception's message and stack trace without suppressed exceptions. Suppressed
     * exceptions will be taken from {@code ArtifactResult} or {@link VersionRangeResult}
     * @param newMavenException exception with reconfigured suppressed exceptions
     * @param cause original Maven exception
     * @param resultExceptions
     * @return
     */
    private IOException configureIOException(Exception newMavenException, Exception cause, List<Exception> resultExceptions) {
        newMavenException.setStackTrace(cause.getStackTrace());

        List<String> messages = new ArrayList<>(resultExceptions.size());
        List<Exception> suppressed = new ArrayList<>();
        for (Exception ex : resultExceptions) {
            messages.add(ex.getMessage() == null ? ex.getClass().getName() : ex.getMessage());
            suppressed.add(ex);
        }
        IOException exception = new IOException(newMavenException.getMessage() + ": " + messages, newMavenException);
        for (Exception ex : suppressed) {
            exception.addSuppressed(ex);
        }
        LOG.warn(exception.getMessage(), exception);

        return exception;
    }

    @Override
    public File resolveMetadata(String groupId, String artifactId, String type, String version) throws IOException {
        return resolveMetadata(groupId, artifactId, type, version, null);
    }

    @Override
    public File resolveMetadata(String groupId, String artifactId, String type, String version,
                                Exception previousException) throws IOException {
        try (Context ctx = m_context.customize(ContextOverrides.Builder.create().build())) {
            RepositorySystem system = ctx.repositorySystem();
            RepositorySystemSession session = ctx.repositorySystemSession();
            try {
                Metadata metadata = new DefaultMetadata(groupId, artifactId, version,
                        type, Metadata.Nature.RELEASE_OR_SNAPSHOT);
                List<MetadataRequest> requests = new ArrayList<MetadataRequest>();
                // TODO: previousException may be a hint to alter remote repository list to query
                for (RemoteRepository repository : getRepositories()) {
                    MetadataRequest request = new MetadataRequest(metadata, repository, RESOLVER_CONTEXT);
                    request.setFavorLocalRepository(false);
                    requests.add(request);
                }
                MetadataRequest request = new MetadataRequest(metadata, null, RESOLVER_CONTEXT);
                request.setFavorLocalRepository(true);
                requests.add(request);
                org.apache.maven.artifact.repository.metadata.Metadata mr = new org.apache.maven.artifact.repository.metadata.Metadata();
                mr.setModelVersion("1.1.0");
                mr.setGroupId(metadata.getGroupId());
                mr.setArtifactId(metadata.getArtifactId());
                mr.setVersioning(new Versioning());
                boolean merged = false;
                List<MetadataResult> results = system.resolveMetadata(session, requests);
                for (MetadataResult result : results) {
                    if (result.getMetadata() != null && result.getMetadata().getFile() != null) {
                        FileInputStream fis = new FileInputStream(result.getMetadata().getFile());
                        org.apache.maven.artifact.repository.metadata.Metadata m = new MetadataXpp3Reader().read(fis, false);
                        fis.close();
                        if (m.getVersioning() != null) {
                            mr.getVersioning().setLastUpdated(latestTimestamp(mr.getVersioning().getLastUpdated(), m.getVersioning().getLastUpdated()));
                            mr.getVersioning().setLatest(latestVersion(mr.getVersioning().getLatest(), m.getVersioning().getLatest()));
                            mr.getVersioning().setRelease(latestVersion(mr.getVersioning().getRelease(), m.getVersioning().getRelease()));
                            for (String v : m.getVersioning().getVersions()) {
                                if (!mr.getVersioning().getVersions().contains(v)) {
                                    mr.getVersioning().getVersions().add(v);
                                }
                            }
                            mr.getVersioning().getSnapshotVersions().addAll(m.getVersioning().getSnapshotVersions());
                        }
                        merged = true;
                    }
                }
                if (merged) {
                    Collections.sort(mr.getVersioning().getVersions(), VERSION_COMPARATOR);
                    Collections.sort(mr.getVersioning().getSnapshotVersions(), SNAPSHOT_VERSION_COMPARATOR);
                    File tmpFile = Files.createTempFile("mvn-", ".tmp").toFile();
                    try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
                        new MetadataXpp3Writer().write(fos, mr);
                    }
                    return tmpFile;
                }
                return null;
            } catch (Exception e) {
                throw new IOException("Unable to resolve metadata", e);
            }
        }
    }

    @Override
    public void upload(String groupId, String artifactId, String classifier, String extension, String version, File file) throws IOException {
        try (Context ctx = m_context.customize(ContextOverrides.Builder.create().build())) {
            RepositorySystem system = ctx.repositorySystem();
            RepositorySystemSession session = ctx.repositorySystemSession();
            try {
                Artifact artifact = new DefaultArtifact(groupId, artifactId, classifier, extension, version,
                        null, file);
                InstallRequest request = new InstallRequest();
                request.addArtifact(artifact);
                system.install(session, request);
            } catch (Exception e) {
                throw new IOException("Unable to install artifact", e);
            }
        }
    }

    @Override
    public void uploadMetadata(String groupId, String artifactId, String type, String version, File file) throws IOException {
        try (Context ctx = m_context.customize(ContextOverrides.Builder.create().build())) {
            RepositorySystem system = ctx.repositorySystem();
            RepositorySystemSession session = ctx.repositorySystemSession();
            try {
                Metadata metadata = new DefaultMetadata(groupId, artifactId, version,
                        type, Metadata.Nature.RELEASE_OR_SNAPSHOT,
                        file);
                InstallRequest request = new InstallRequest();
                request.addMetadata(metadata);
                system.install(session, request);
            } catch (Exception e) {
                throw new IOException("Unable to install metadata", e);
            }
        }
    }

    @Override
    public RetryChance isRetryableException(Exception exception) {
        RetryChance retry = RetryChance.NEVER;

        RepositoryException aetherException = findAetherException(exception);

        if (aetherException instanceof ArtifactResolutionException) {
            // aggregate case - exception that contains exceptions - usually per repository
            ArtifactResolutionException resolutionException = (ArtifactResolutionException) aetherException;
            if (resolutionException.getResult() != null) {
                for (Exception ex : resolutionException.getResult().getExceptions()) {
                    RetryChance singleRetry = isRetryableException(ex);
                    if (retry.chance() < singleRetry.chance()) {
                        retry = singleRetry;
                    }
                }
            }
        } else if (aetherException != null) {
            // single exception case

            if (aetherException instanceof ArtifactNotFoundException) {
                // very little chance we'll find the artifact next time
                retry = RetryChance.NEVER;
            } else if (aetherException instanceof MetadataNotFoundException) {
                retry = RetryChance.NEVER;
            } else if (aetherException instanceof ArtifactTransferException
                    || aetherException instanceof MetadataTransferException) {
                // we could try again
                Throwable root = rootException(aetherException);
                if (root instanceof SocketTimeoutException) {
                    // we could try again - but without assuming we'll succeed eventually
                    retry = RetryChance.LOW;
                } else if (root instanceof ConnectException) {
                    // "connection refused" - not retryable
                    retry = RetryChance.NEVER;
                } else if (root instanceof NoRouteToHostException) {
                    // not retryable
                    retry = RetryChance.NEVER;
                }
            } else {
                // general aether exception - let's fallback to NEVER, as retryable cases should be
                // handled explicitly
                retry = RetryChance.NEVER;
            }
        } else {
            // we don't know about non-aether exceptions, so let's allow
            retry = RetryChance.UNKNOWN;
        }

        return retry;
    }

    /**
     * Find top-most Aether exception
     * @param e
     * @return
     */
    protected RepositoryException findAetherException(Exception e) {
        Throwable ex = e;
        while (ex != null && !(ex instanceof RepositoryException)) {
            ex = ex.getCause();
        }
        return ex == null ? null : (RepositoryException) ex;
    }

    /**
     * Find root exception
     * @param ex
     * @return
     */
    protected Throwable rootException(Exception ex) {
        Throwable root = ex;
        while (true) {
            if (root.getCause() != null) {
                root = root.getCause();
            } else {
                break;
            }
        }
        return root;
    }

    private final Comparator<String> VERSION_COMPARATOR = new Comparator<String>() {
        @Override
        public int compare(String v1, String v2) {
            try {
                Version vv1 = new GenericVersionScheme().parseVersion(v1);
                Version vv2 = new GenericVersionScheme().parseVersion(v2);
                return vv1.compareTo(vv2);
            } catch (Exception e) {
                return v1.compareTo(v2);
            }
        }
    };

    private final Comparator<SnapshotVersion> SNAPSHOT_VERSION_COMPARATOR = new Comparator<SnapshotVersion>() {
        @Override
        public int compare(SnapshotVersion o1, SnapshotVersion o2) {
            int c = VERSION_COMPARATOR.compare(o1.getVersion(), o2.getVersion());
            if (c == 0) {
                c = o1.getExtension().compareTo(o2.getExtension());
            }
            if (c == 0) {
                c = o1.getClassifier().compareTo(o2.getClassifier());
            }
            return c;
        }
    };

    private String latestTimestamp(String t1, String t2) {
        if (t1 == null) {
            return t2;
        } else if (t2 == null) {
            return t1;
        } else {
            return t1.compareTo(t2) < 0 ? t2 : t1;
        }
    }

    private String latestVersion(String v1, String v2) {
        if (v1 == null) {
            return v2;
        } else if (v2 == null) {
            return v1;
        } else {
            return VERSION_COMPARATOR.compare(v1, v2) < 0 ? v2 : v1;
        }
    }

    /**
     * Tries to resolve versions = LATEST using an open range version query. If it succeeds, version
     * of artifact is set to the highest available version.
     *
     * @param context
     *            to be used.
     * @param artifact
     *            to be used
     *
     * @return an artifact with version set properly (highest if available)
     *
     * @throws org.eclipse.aether.resolution.VersionRangeResolutionException
     *             in case of resolver errors.
     */
    private Artifact resolveLatestVersionRange(Context context,
                                               List<RemoteRepository> remoteRepos, Artifact artifact)
            throws VersionRangeResolutionException {

        VersionRangeResult versionResult = context.repositorySystem().resolveVersionRange(context.repositorySystemSession(),
                new VersionRangeRequest(artifact, remoteRepos, RESOLVER_CONTEXT));
        if (versionResult != null) {
            Version v = versionResult.getHighestVersion();
            if (v != null) {
                artifact = artifact.setVersion(v.toString());
            } else {
                throw new VersionRangeResolutionException(versionResult,
                        "No highest version found for " + artifact);
            }
        }
        return artifact;
    }

    public static RemoteRepository toRemoteRepository(MavenRepositoryURL repo) {
        String releasesUpdatePolicy = repo.getReleasesUpdatePolicy();
        if (releasesUpdatePolicy == null || releasesUpdatePolicy.isEmpty()) {
            releasesUpdatePolicy = UPDATE_POLICY_DAILY;
        }
        String releasesChecksumPolicy = repo.getReleasesChecksumPolicy();
        if (releasesChecksumPolicy == null || releasesChecksumPolicy.isEmpty()) {
            releasesChecksumPolicy = CHECKSUM_POLICY_WARN;
        }
        String snapshotsUpdatePolicy = repo.getSnapshotsUpdatePolicy();
        if (snapshotsUpdatePolicy == null || snapshotsUpdatePolicy.isEmpty()) {
            snapshotsUpdatePolicy = UPDATE_POLICY_DAILY;
        }
        String snapshotsChecksumPolicy = repo.getSnapshotsChecksumPolicy();
        if (snapshotsChecksumPolicy == null || snapshotsChecksumPolicy.isEmpty()) {
            snapshotsChecksumPolicy = CHECKSUM_POLICY_WARN;
        }
        RemoteRepository.Builder builder =
                new RemoteRepository.Builder( repo.getId(), REPO_TYPE, repo.getURL().toExternalForm() );
        RepositoryPolicy releasePolicy =
                new RepositoryPolicy( repo.isReleasesEnabled(), releasesUpdatePolicy, releasesChecksumPolicy );
        builder.setReleasePolicy( releasePolicy );
        RepositoryPolicy snapshotPolicy =
                new RepositoryPolicy( repo.isSnapshotsEnabled(), snapshotsUpdatePolicy, snapshotsChecksumPolicy );
        builder.setSnapshotPolicy( snapshotPolicy );
        return builder.build();
    }
}
