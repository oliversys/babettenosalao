package br.com.oliversys.microservices.babettenosalao.gateway;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;

//@Configuration
//public class OAuth2Config {

	// @Value("classpath:schema.sql")
	// private Resource schemaScript;
	//
	// @Autowired
	// private Environment env;
	//
	// @Bean
	// public DataSourceInitializer dataSourceInitializer(DataSource dataSource)
	// {
	// DataSourceInitializer initializer = new DataSourceInitializer();
	// initializer.setDataSource(dataSource);
	// initializer.setDatabasePopulator(databasePopulator());
	// return initializer;
	// }
	//
	// private DatabasePopulator databasePopulator() {
	// ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
	// populator.addScript(schemaScript);
	// return populator;
	// }
	//
	// @Bean
	// public DataSource dataSource() {
	// DriverManagerDataSource dataSource = new DriverManagerDataSource();
	// dataSource.setDriverClassName(env.getProperty("jdbc.driverClassName"));
	// dataSource.setUrl(env.getProperty("jdbc.url"));
	// dataSource.setUsername(env.getProperty("jdbc.user"));
	// dataSource.setPassword(env.getProperty("jdbc.pass"));
	// return dataSource;
	// }

	// @Configuration
	// @EnableAuthorizationServer
	// public class AuthServerOAuth2Config extends
	// AuthorizationServerConfigurerAdapter {
	// @Autowired
	// @Qualifier("authenticationManagerBean")
	// private AuthenticationManager authenticationManager;
	//
	// @Bean
	// public JwtAccessTokenConverter accessTokenConverter() {
	// return new JwtAccessTokenConverter();
	// }
	//
	// @Override
	// public void configure(AuthorizationServerSecurityConfigurer oauthServer)
	// throws Exception {
	// oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	// }
	//
	// @Override
	// public void configure(ClientDetailsServiceConfigurer clients) throws
	// Exception {
	// clients.jdbc(dataSource()).withClient("sampleClientId").authorizedGrantTypes("implicit").scopes("read")
	// .autoApprove(true).and().withClient("clientIdPassword").secret("secret")
	// .authorizedGrantTypes("password", "authorization_code",
	// "refresh_token").scopes("read");
	// }
	//
	// @Override
	// public void configure(AuthorizationServerEndpointsConfigurer endpoints)
	// throws Exception {
	// endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager);
	// }
	//
	// @Bean
	// public TokenStore tokenStore() {
	// return new JdbcTokenStore(dataSource());
	// }
	// }
//
//}
