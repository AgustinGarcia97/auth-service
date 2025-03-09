/* Copyright 2020 the original author or authors. All rights reserved. */
package com.idea.authservice.shared.exceptions.authexceptions.handler;


import com.idea.authservice.shared.exceptions.authexceptions.ApiError;
import com.idea.authservice.shared.exceptions.authexceptions.ApiSubError;
import com.idea.authservice.shared.exceptions.authexceptions.ItemNotFoundException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import static org.springframework.http.HttpStatus.*;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ItemNotFoundException.class)
    protected ResponseEntity<Object> handleItemNotFoundException(Exception ex, WebRequest request) {
        return notFound(ex, request);
    }

    @ExceptionHandler(IllegalStateException.class)
    protected ResponseEntity<Object> handleIllegalStateException(Exception ex, WebRequest request) {
        return conflict(ex, request);
    }

    @ExceptionHandler({IllegalArgumentException.class})
    protected ResponseEntity<Object> handleIllegalArgumentException(IllegalArgumentException ex, WebRequest request) {
        return badRequest(ex, new HttpHeaders(), request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return badRequest(ex, headers, request);
    }


    private ResponseEntity<Object> notFound(Exception ex, WebRequest request) {
        var apiError = ApiError.builder().status(NOT_FOUND).message(ex.getMessage()).build();

        return handleExceptionInternal(ex, apiError, new HttpHeaders(), apiError.getStatus(), request);
    }

    private ResponseEntity<Object> unauthorized(Exception ex, WebRequest request) {
        var apiError = ApiError.builder().status(UNAUTHORIZED).message(ex.getMessage()).build();

        return handleExceptionInternal(ex, apiError, new HttpHeaders(), apiError.getStatus(), request);
    }

    private ResponseEntity<Object> conflict(Exception ex, WebRequest request) {
        var apiError = ApiError.builder().status(CONFLICT).message(ex.getMessage()).build();

        return handleExceptionInternal(ex, apiError, new HttpHeaders(), apiError.getStatus(), request);
    }

    private ResponseEntity<Object> badRequest(MethodArgumentNotValidException ex, HttpHeaders headers, WebRequest request) {
        var subErrors = ex.getBindingResult().getFieldErrors().stream().map(error -> ApiSubError.builder()
                .object(error.getObjectName())
                .field(error.getField())
                .message(error.getDefaultMessage())
                .build()
        ).toList();
        var errorDetails = ApiError.builder().status(BAD_REQUEST).message("Validation Error").subErrors(subErrors).build();
        return handleExceptionInternal(ex, errorDetails, headers, errorDetails.getStatus(), request);
    }

    private ResponseEntity<Object> badRequest(IllegalArgumentException ex, HttpHeaders headers, WebRequest request) {
        var apiError = new ApiError(BAD_REQUEST, ex.getMessage());

        return handleExceptionInternal(ex, apiError, headers, apiError.getStatus(), request);
    }

}