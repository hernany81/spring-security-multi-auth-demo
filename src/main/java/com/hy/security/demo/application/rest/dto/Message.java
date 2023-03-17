package com.hy.security.demo.application.rest.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record Message(UUID id, String message, LocalDateTime postedTimestamp) {
}
