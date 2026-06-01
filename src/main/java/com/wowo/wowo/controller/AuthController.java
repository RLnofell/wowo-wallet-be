package com.wowo.wowo.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.wowo.wowo.data.dto.CreateUserDTO;
import com.wowo.wowo.data.dto.SSOData;
import com.wowo.wowo.data.dto.UserDTO;
import com.wowo.wowo.data.mapper.UserMapper;
import com.wowo.wowo.model.User;
import com.wowo.wowo.service.AuthService;
import com.wowo.wowo.service.JwtService;
import com.wowo.wowo.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@AllArgsConstructor
@RequestMapping("v1/auth")
@Tag(name = "Auth", description = "Xác thực")
public class AuthController {

    private final UserService userService;
    private final AuthService authService;
    private final UserMapper userMapperImpl;

    @PostMapping("/sign-up")
    public ResponseEntity<?> signUp(@Valid @RequestBody CreateUserDTO createUserDTO) {
        User user = authService.register(createUserDTO);
        String token = JwtService.generateToken(user);
        return ResponseEntity.ok(Map.of(
                "user", userMapperImpl.toDto(user),
                "Token", token
        ));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");
        if (email == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "Vui lòng nhập email và mật khẩu"));
        }
        User user = authService.login(email, password);
        String token = JwtService.generateToken(user);
        return ResponseEntity.ok(Map.of(
                "user", userMapperImpl.toDto(user),
                "Token", token
        ));
    }

    @RequestMapping("/sso")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> handleCallback(Authentication authentication) {
        DecodedJWT decodedJWT = (DecodedJWT) authentication.getDetails();
        String email = decodedJWT.getClaim("email")
                .asString();
        String userId = decodedJWT.getClaim("userId")
                .asString();
        String partnerId = decodedJWT.getClaim("partnerId")
                .asString();
        String username = decodedJWT.getClaim("username")
                .asString();
        String firstName = decodedJWT.getClaim("firstName")
                .asString();
        String lastName = decodedJWT.getClaim("lastName")
                .asString();
        String role = decodedJWT.getClaim("role")
                .asString();
        String name = decodedJWT.getClaim("name")
                .asString();

        switch (role) {
            case "user" -> {
                SSOData ssoData = new SSOData(email, userId, username, firstName, lastName, name);
                userService.createUser(ssoData);
            }
            case "partner" -> {
                SSOData ssoData = new SSOData(email, partnerId, username, firstName, lastName,
                        name);
            }

            default -> throw new IllegalStateException("Unexpected value: " + role);
        }

        return ResponseEntity.ok()
                .build();
    }
}
