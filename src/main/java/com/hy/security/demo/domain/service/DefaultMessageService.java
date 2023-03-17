package com.hy.security.demo.domain.service;

import com.hy.security.demo.domain.Message;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DefaultMessageService implements MessageService {

    @Override
    public List<Message> getMessagesByUserName(String username) {
        throw new RuntimeException("Method not implemented");
    }

    @Override
    public List<Message> getMessagesForInternalUsers() {
        throw new RuntimeException("Method not implemented");
    }

    @Override
    public List<Message> getMessagesForSsoUsers() {
        throw new RuntimeException("Method not implemented");
    }
}
