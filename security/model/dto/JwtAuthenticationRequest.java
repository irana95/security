package com.app.petmate.security.model.dto;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtAuthenticationRequest {

    private String username;

    private String password;

}