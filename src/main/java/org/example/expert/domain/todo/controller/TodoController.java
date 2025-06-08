package org.example.expert.domain.todo.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.expert.config.security.UserPrincipal;
import org.example.expert.domain.common.dto.ApiResponse;
import org.example.expert.domain.common.dto.PageResponse;
import org.example.expert.domain.todo.dto.request.TodoSaveRequest;
import org.example.expert.domain.todo.dto.response.TodoResponse;
import org.example.expert.domain.todo.dto.response.TodoSaveResponse;
import org.example.expert.domain.todo.service.TodoService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class TodoController {

    private final TodoService todoService;

    @PostMapping("/todos")
    public ResponseEntity<ApiResponse<TodoSaveResponse>> saveTodo(
            @AuthenticationPrincipal UserPrincipal userPrincipal,
            @Valid @RequestBody TodoSaveRequest todoSaveRequest
    ) {
        TodoSaveResponse response = todoService.saveTodo(userPrincipal.getId(), todoSaveRequest);
        return ResponseEntity.ok(ApiResponse.success(response, "할일이 등록되었습니다."));
    }

    @GetMapping("/todos")
    public ResponseEntity<ApiResponse<PageResponse<TodoResponse>>> getTodos(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Page<TodoResponse> todos = todoService.getTodos(page, size);
        PageResponse<TodoResponse> pageResponse = PageResponse.of(todos);
        return ResponseEntity.ok(ApiResponse.success(pageResponse));
    }

    @GetMapping("/todos/{todoId}")
    public ResponseEntity<ApiResponse<TodoResponse>> getTodo(@PathVariable long todoId) {
        TodoResponse response = todoService.getTodo(todoId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }
}