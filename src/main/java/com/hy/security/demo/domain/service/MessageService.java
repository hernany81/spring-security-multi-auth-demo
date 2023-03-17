package com.hy.security.demo.domain.service;

import com.hy.security.demo.domain.Message;

import java.util.List;

public interface MessageService {
    List<Message> getMessagesByUserName(String username);
    List<Message> getMessagesForInternalUsers();
    List<Message> getMessagesForSsoUsers();
}
