package com.userStorageSPI.config

import com.userStorageSPI.controller.getRolesFromToken
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
class KeycloakConfig : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
            .authorizeRequests().antMatchers("/").permitAll()
            .and()
            .authorizeRequests().anyRequest().authenticated()
            .and()
            .oauth2Login {
                it.userInfoEndpoint { u ->
                    u.oidcUserService(oidcUserService())
                }
            }
            .logout {
                it.logoutSuccessHandler(oidcLogoutSuccessHandler())
            }

    }

    @Bean
    fun oidcUserService(): OAuth2UserService<OidcUserRequest, OidcUser> {
        val delegate = OidcUserService()

        return OAuth2UserService { userRequest ->
            var oidcUser = delegate.loadUser(userRequest)
            val accessToken = userRequest.accessToken
            val mappedAuthorities = getRolesFromToken(accessToken.tokenValue)
            oidcUser = DefaultOidcUser(mappedAuthorities, oidcUser.idToken, oidcUser.userInfo)

            oidcUser
        }
    }

    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        val clientRegistration = ClientRegistrations
            .fromIssuerLocation("http://localhost:8080/auth/realms/UserInfo")
            .clientId("UserInfo")
            .clientSecret("bd25faec-36ad-40f1-9ca9-54f762746842")
            .scope("openid")
            .build()
        return InMemoryClientRegistrationRepository(clientRegistration)
    }


    private fun oidcLogoutSuccessHandler(): LogoutSuccessHandler {
        val oidcLogoutSuccessHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}")
        return oidcLogoutSuccessHandler
    }
}