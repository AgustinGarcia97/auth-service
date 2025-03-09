/* Copyright 2020 the original author or authors. All rights reserved. */
package com.idea.authservice.infraestructure.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.modelmapper.convention.MatchingStrategies.STRICT;

@Configuration
public class ModelMapperConfiguration {

    @Bean
    public ModelMapper modelMapper() {
        final ModelMapper modelMapper = new ModelMapper();

        modelMapper.getConfiguration().setMatchingStrategy(STRICT);
        modelMapper.getConfiguration().setSkipNullEnabled(true);

        return modelMapper;
    }
}
