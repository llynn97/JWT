package com.example.jwt.controller;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

   private final BCryptPasswordEncoder bCryptPasswordEncoder;
   private final UserRepository userRepository;


    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping("api/v1/user")
    public String user(){
        return "user";
    }

    @GetMapping("api/v1/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("api/v1/admin")
    public String admin(){
        return "admin";
    }


}
