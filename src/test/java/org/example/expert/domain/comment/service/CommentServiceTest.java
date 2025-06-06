package org.example.expert.domain.comment.service;

import org.example.expert.domain.comment.dto.request.CommentSaveRequest;
import org.example.expert.domain.comment.dto.response.CommentSaveResponse;
import org.example.expert.domain.comment.entity.Comment;
import org.example.expert.domain.comment.repository.CommentRepository;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.todo.repository.TodoRepository;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.domain.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class CommentServiceTest {

    @Mock
    private CommentRepository commentRepository;
    @Mock
    private TodoRepository todoRepository;
    @Mock
    private UserRepository userRepository;
    @InjectMocks
    private CommentService commentService;

    @Test
    public void comment_등록_중_사용자를_찾지_못해_에러가_발생한다() {
        // given
        Long userId = 1L;
        long todoId = 1L;
        CommentSaveRequest request = new CommentSaveRequest("contents");

        given(userRepository.findById(userId)).willReturn(Optional.empty());

        // when & then
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                commentService.saveComment(userId, todoId, request));

        assertEquals("User not found", exception.getMessage());
    }

    @Test
    public void comment_등록_중_할일을_찾지_못해_에러가_발생한다() {
        // given
        Long userId = 1L;
        long todoId = 1L;
        CommentSaveRequest request = new CommentSaveRequest("contents");
        User user = new User("email@test.com", "password", UserRole.USER);

        given(userRepository.findById(userId)).willReturn(Optional.of(user));
        given(todoRepository.findById(anyLong())).willReturn(Optional.empty());

        // when & then
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                commentService.saveComment(userId, todoId, request));

        assertEquals("Todo not found", exception.getMessage());
    }

    @Test
    public void comment를_정상적으로_등록한다() {
        // given
        Long userId = 1L;
        long todoId = 1L;
        CommentSaveRequest request = new CommentSaveRequest("contents");

        User user = new User("email@test.com", "password", UserRole.USER);
        ReflectionTestUtils.setField(user, "id", userId);

        Todo todo = new Todo("title", "contents", "weather", user);
        Comment comment = new Comment(request.getContents(), user, todo);

        given(userRepository.findById(userId)).willReturn(Optional.of(user));
        given(todoRepository.findById(anyLong())).willReturn(Optional.of(todo));
        given(commentRepository.save(any())).willReturn(comment);

        // when
        CommentSaveResponse result = commentService.saveComment(userId, todoId, request);

        // then
        assertNotNull(result);
        assertEquals(request.getContents(), result.getContents());
        assertEquals(user.getId(), result.getUser().getId());
        assertEquals(user.getEmail(), result.getUser().getEmail());
    }
}
