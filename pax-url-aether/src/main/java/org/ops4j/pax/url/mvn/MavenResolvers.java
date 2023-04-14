/**
 *  Copyright 2014, Guillaume Nodet.
 *
 *  Red Hat licenses this file to you under the Apache License, version
 *  2.0 (the "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
package org.ops4j.pax.url.mvn;

import java.net.MalformedURLException;
import java.util.Dictionary;

import org.ops4j.pax.url.mvn.internal.AetherBasedResolver;
import org.ops4j.pax.url.mvn.internal.config.MavenConfigurationImpl;
import org.ops4j.util.property.DictionaryPropertyResolver;
import org.ops4j.util.property.PropertiesPropertyResolver;

public final class MavenResolvers {

    public static MavenResolver createMavenResolver(Dictionary<String, String> properties, String pid) throws
            MalformedURLException
    {
        PropertiesPropertyResolver syspropsResolver = new PropertiesPropertyResolver(System.getProperties());
        DictionaryPropertyResolver propertyResolver = new DictionaryPropertyResolver(properties, syspropsResolver);
        MavenConfigurationImpl config = new MavenConfigurationImpl(propertyResolver, pid);
        return new AetherBasedResolver(config);
    }

    private MavenResolvers() { }
}
