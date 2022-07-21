package com.userStorageSPI.controller

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import java.util.*

@Controller
class KeycloakController {
    @GetMapping("/private")
    fun private(
        @RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
        @AuthenticationPrincipal oauth2User: OAuth2User
    ): String {
        return "private"
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/private/admin")
    fun privateAdmin(
        @RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
        @AuthenticationPrincipal oauth2User: OAuth2User
    ): String {
        return "private"
    }

    @GetMapping("/")
    fun public() = "public"

}


fun getRolesFromToken(token: String): HashSet<GrantedAuthority> {
    val chunks = token.split(".");
    val decoder = Base64.getDecoder();
    val payload = String(decoder.decode(chunks[1]))
    val map = ObjectMapper().readValue<MutableMap<String, Any>>(payload)
    println(map.toString())
    val ra = map["resource_access"] as Map<String, Any>
    val ad = ra["UserInfo"] as Map<String, String>
    val roles = ad["roles"] as ArrayList<String>
    return roles.map { SimpleGrantedAuthority(it) }.toHashSet()
}