package com.app.petmate.security.controller;

import com.app.petmate.model.dto.UserDto;
import com.app.petmate.security.model.dto.JwtAuthenticationRequest;
import com.app.petmate.security.model.dto.JwtAuthenticationResponse;
import com.app.petmate.security.service.AuthenticationService;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api")
@RestController
@CrossOrigin(origins = "http://localhost:63342")
public class AuthenticationController {

    private final AuthenticationService service;


    public AuthenticationController(AuthenticationService service) {
        this.service = service;

    }

    @PostMapping("/auth")
    public JwtAuthenticationResponse signIn(@RequestBody JwtAuthenticationRequest request) {
        return service.createAuthenticationToken(request);
    }

    @PutMapping("/logout")
    public void logOut(@RequestParam String username){
        service.logOut(username);
    }

    @PostMapping("/reg")
    public void reg(@RequestBody UserDto user){

    }
}