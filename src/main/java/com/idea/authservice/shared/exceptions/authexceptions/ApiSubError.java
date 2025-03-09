/* Copyright 2020 the original author or authors. All rights reserved. */
package com.idea.authservice.shared.exceptions.authexceptions;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ApiSubError {

    private String object;

    private String field;

    private String message;

}
