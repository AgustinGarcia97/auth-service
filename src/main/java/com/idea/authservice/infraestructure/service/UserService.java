package com.idea.authservice.infraestructure.service;

import com.idea.authservice.application.request.auth.UserResponse;
import com.idea.authservice.domain.model.User;
import com.idea.authservice.domain.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    public UserResponse getByUsername(String username){
        Optional<User> userSearched =  userRepository.findByUsername(username);
        UserResponse userResponse = new UserResponse();
        if(userSearched.isPresent()){
            userResponse.setUsername(userSearched.get().getUsername());
            userResponse.setPassword(userSearched.get().getPassword());
            userResponse.setRole(String.valueOf(userSearched.get().getRole()));
        }
        return userResponse;

    }
}
