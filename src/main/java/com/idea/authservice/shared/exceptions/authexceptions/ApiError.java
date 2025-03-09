/* Copyright 2020 the original author or authors. All rights reserved. */
package com.idea.authservice.shared.exceptions.authexceptions;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiError {

	private HttpStatus status;

	private String message;

	private List<ApiSubError> subErrors;

	public ApiError(HttpStatus status, String message) {
		this();
		this.status = status;
		this.message = message;
	}

}
