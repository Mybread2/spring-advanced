package org.example.expert.domain.practice;

import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.todo.repository.TodoRepository;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.domain.user.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
@Transactional
class JpqlPracticeTest {
    
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TodoRepository todoRepository;

    @Test
    @DisplayName("특정 사용자의 할일 개수를 정확히 세어야 한다")
    void countTodosByUserId_should_return_exact_count() {
        // given
        User testUser = new User("test@example.com", "password", UserRole.USER);
        User savedUser = userRepository.save(testUser);

        Todo todo1 = new Todo("할일 1", "내용 1", "맑음", savedUser);
        Todo todo2 = new Todo("할일 2", "내용 2", "흐림", savedUser);
        Todo todo3 = new Todo("할일 3", "내용 3", "비", savedUser);
        todoRepository.saveAll(List.of(todo1, todo2, todo3));

        // when
        Long actualCount = todoRepository.countTodosByUserId(savedUser.getId());

        // then
        assertThat(actualCount).isEqualTo(3L);
    }
}
