package com.app.petmate.security.service;

import com.app.petmate.mappers.UserMapper;
import com.app.petmate.model.dto.UserDto;
import com.app.petmate.model.entity.UserEntity;
import com.app.petmate.repository.UserRepository;
import com.app.petmate.security.exceptions.AuthenticationException;
import com.app.petmate.security.model.Role;
import com.app.petmate.security.model.dto.JwtAuthenticationRequest;
import com.app.petmate.security.model.dto.JwtAuthenticationResponse;
import com.app.petmate.security.util.TokenUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.Random;

@Service
public class AuthenticationService {

    private final TokenUtils tokenUtils;

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    public AuthenticationService(TokenUtils tokenUtils,
                                 AuthenticationManager authenticationManager,
                                 UserRepository userRepository) {
        this.tokenUtils = tokenUtils;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
    }


    public JwtAuthenticationResponse createAuthenticationToken(JwtAuthenticationRequest request) {
        authenticate(request.getUsername(), request.getPassword());
        String token = tokenUtils.generateToken(request.getUsername());
        return new JwtAuthenticationResponse(token);
    }

    public void authenticate(String username, String password) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new AuthenticationException("User is disabled", e);
        } catch (BadCredentialsException e) {
            throw new AuthenticationException("Bad credentials", e);
        }
    }

    public boolean emailValidation(String email){
        boolean valid = email.matches("^[A-z0-9._%+-]+@[A-z0-9.-]+\\.[A-z]{2,6}$");
        return valid;
    }

    public void logOut(String username){

    }

    public String passwordGenerator(){
        Random random = new Random();
        int len = (int) (Math.random()*10);
        return random.ints(48, 122)
                .filter(t -> (t < 57 || t > 65) && (t < 90 || t > 97))
                .mapToObj(t -> (char) t)
                .limit(10)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }

    public UserEntity signUp(UserDto user){
        UserEntity checkEmail = userRepository.getByEmail(user.getEmail());
        UserEntity checkUsernme = userRepository.getByEmail(user.getUsername());
        if (checkEmail == null && checkUsernme == null && emailValidation(user.getEmail())){
            String password = new BCryptPasswordEncoder().encode(user.getPassword());
            UserEntity userEntity = UserMapper.dtoToEntity(user);
            userEntity.setRole(Role.ROLE_USER.toString());
            userEntity.setPassword(password);
            userRepository.save(userEntity);
            return userEntity;
        } else {
            throw new AuthenticationException("This email is already exists");
        }
    }
}
