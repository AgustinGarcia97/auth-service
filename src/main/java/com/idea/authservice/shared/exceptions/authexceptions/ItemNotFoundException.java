/* Copyright 2020 the original author or authors. All rights reserved. */
package com.idea.authservice.shared.exceptions.authexceptions;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class ItemNotFoundException extends RuntimeException {

	public ItemNotFoundException(String message) {
		super(message);
	}

	private static final long serialVersionUID = -6876745701308382277L;
}