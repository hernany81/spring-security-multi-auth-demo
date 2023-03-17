package com.hy.security.demo.domain;

import java.time.LocalDateTime;
import java.util.UUID;

public class Message {

    private final UUID id;
    private final String username;
    private final String message;
    private final LocalDateTime postedTimestamp;

    public Message(UUID id, String username, String message, LocalDateTime postedTimestamp) {
        this.id = id;
        this.username = username;
        this.message = message;
        this.postedTimestamp = postedTimestamp;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getMessage() {
        return message;
    }

    public LocalDateTime getPostedTimestamp() {
        return postedTimestamp;
    }
}
