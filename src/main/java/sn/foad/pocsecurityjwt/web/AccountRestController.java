package sn.foad.pocsecurityjwt.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import sn.foad.pocsecurityjwt.entities.PocRoles;
import sn.foad.pocsecurityjwt.entities.PocUsers;
import sn.foad.pocsecurityjwt.service.PocAccountService;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private final PocAccountService accountService;

    public AccountRestController(PocAccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/pocusers")
    @PostAuthorize("hasAuthority('USER')")
    public List<PocUsers> pocUsers() {
        return accountService.listUsers();
    }

    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping(path = "/pocusers")
    public PocUsers saveUser(@RequestBody PocUsers pocUsers) {
        return accountService.addUser(pocUsers);
    }

    @PostMapping(path = "/pocroles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public PocRoles saveRole(@RequestBody PocRoles pocRoles) {
        return accountService.addRole(pocRoles);
    }

    @PostMapping(path = "/pocaddroles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    @GetMapping("/refreshToken")
    public void tokenRefresh(HttpServletRequest request, HttpServletResponse httpServletResponse) throws IOException {
        String authToken = request.getHeader("Authorization");
        if (authToken != null && authToken.startsWith("Bearer ")) {
            try {
                authToken = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("monSecretPass");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(authToken);
                String username = decodedJWT.getSubject();
                PocUsers pocUsers = accountService.loadUserByUsername(username);

                String accessTokenJwt = JWT.create()
                        .withSubject(pocUsers.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", pocUsers.getPocRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String, String> idToken = new HashMap<>();
                idToken.put("access_token", accessTokenJwt);
                idToken.put("refresh_token", authToken);
                httpServletResponse.setContentType("application/json");
                new ObjectMapper().writeValue(httpServletResponse.getOutputStream(), idToken);

            } catch (Exception e) {
                httpServletResponse.setHeader("error-message", e.getMessage());
                httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            }

        } else {
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
        }
    }
}

@Data
class RoleUserForm {
   private String username;
   private String roleName;
}
