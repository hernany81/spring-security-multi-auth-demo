package com.hy.security.demo.application.rest;

import com.hy.security.demo.application.rest.dto.Message;
import com.hy.security.demo.domain.service.MessageService;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;


@RestController
@RequestMapping(path = "/api", produces = MediaType.APPLICATION_JSON_VALUE)
public class MessagesController {

    private final MessageService messageService;

    public MessagesController(MessageService messageService) {
        this.messageService = messageService;
    }

    @GetMapping("/messages")
    public List<Message> getCurrentUserMessages(Authentication principal) {
        var userName = principal.getName();

        return mapToDto(this.messageService.getMessagesByUserName(userName));
    }

    @GetMapping("/internal-users-messages")
    @PreAuthorize("hasAuthority('BASIC_AUTH_USER')")
    public List<Message> getInternalUsersMessages() {
        return mapToDto(this.messageService.getMessagesForInternalUsers());
    }

    @GetMapping("/sso-users-messages")
    @PreAuthorize("hasAuthority('OIDC_USER')")
    public List<Message> getSsoUsersMessages() {
        return mapToDto(this.messageService.getMessagesForSsoUsers());
    }

    private List<Message> mapToDto(List<com.hy.security.demo.domain.Message> messages) {
        return messages
                .stream()
                .map(m ->
                        new Message(m.getId(), m.getMessage(), m.getPostedTimestamp())
                )
                .toList();
    }
}
