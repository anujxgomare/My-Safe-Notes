package com.secure.notes.config;

import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.security.jwt.JwtUtils;
import com.secure.notes.security.services.UserDetailsImpl;
import com.secure.notes.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        OAuth2AuthenticationToken token =
                (OAuth2AuthenticationToken) authentication;

        DefaultOAuth2User oauthUser =
                (DefaultOAuth2User) token.getPrincipal();

        Map<String, Object> attributes = oauthUser.getAttributes();
        String provider = token.getAuthorizedClientRegistrationId();

        String username;
        String email;

        // ================= SAFE ATTRIBUTE HANDLING =================
        if ("github".equals(provider)) {
            username = attributes.get("login").toString();
            email = attributes.get("email") != null
                    ? attributes.get("email").toString()
                    : username + "@github.com";
        } else {
            email = attributes.get("email").toString();
            username = email.split("@")[0];
        }

        // ================= FIND OR CREATE USER =================
        User user = userService.findByEmail(email).orElse(null);

        if (user == null) {
            Role role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));

            user = new User();
            user.setUserName(username);
            user.setEmail(email);
            user.setRole(role);
            user.setSignUpMethod(provider);

            user = userService.registerUser(user);
        }

        // ================= CREATE JWT =================
        UserDetailsImpl userDetails = new UserDetailsImpl(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                null,
                false,
                Collections.singletonList(
                        new SimpleGrantedAuthority(user.getRole().getRoleName().name())
                )
        );

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // ================= REDIRECT =================
        String redirectUrl = UriComponentsBuilder
                .fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build()
                .toUriString();

        response.sendRedirect(redirectUrl);
    }
}
