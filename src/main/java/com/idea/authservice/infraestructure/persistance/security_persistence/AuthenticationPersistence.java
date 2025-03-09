package com.idea.authservice.infraestructure.persistance.security_persistence;

import com.idea.authservice.application.request.auth.AuthenticationRequest;
import com.idea.authservice.application.response.AuthenticationResponse;
import com.idea.authservice.application.request.auth.RegisterRequest;
import com.idea.authservice.domain.model.User;
import com.idea.authservice.domain.model.enums.Role;
import com.idea.authservice.domain.repository.UserRepository;
import com.idea.authservice.infraestructure.security.JwtService;
import lombok.RequiredArgsConstructor;

import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationPersistence {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ModelMapper modelMapper;


    public AuthenticationResponse register(RegisterRequest request) {
        System.out.println(passwordEncoder);
        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.valueOf("ADMIN"))
                .build();

        repository.save(user);
        var jwtToken = jwtService.generateToken(user);



        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .username(user.getUsername())
                .userId(user.getId())
                .role(String.valueOf(user.getRole()))
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //autentica
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())); //si esta linea pasa, significa que el usuario esta autenticado dentro del server sin hacer una query de checkeo a la db
        //como se que existe, se busca la info del usuario

        var user = repository.findByUsername(request.getEmail())
                .orElseThrow();

        //si el usuario esta autenticado y encontre la data retorno un token
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .userId(user.getId())
                .username(user.getUsername())
                .role(String.valueOf(user.getRole()))
                .build();
    }
}





