package securitySpringboot.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import securitySpringboot.user.dto.RoleToUserForm;
import securitySpringboot.user.model.Role;
import securitySpringboot.user.model.User;
import securitySpringboot.user.service.UserService;

import java.net.URI;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    @PostMapping("/user/add")
    public ResponseEntity<User> addUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/add").toUriString());
        return ResponseEntity.created(uri).body(userService.addUser(user));
    }
    @PostMapping("/user/adddto")
    public ResponseEntity<User> addUserDto(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/add").toUriString());
        return ResponseEntity.created(uri).body(userService.addUser(user));
    }

    @PostMapping("/role/add")
    public ResponseEntity<Role> addUser(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/add").toUriString());
        return ResponseEntity.created(uri).body(userService.addRole(role));
    }

//세번째 사진 아래 참고
    @PostMapping
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm roleToUserForm){
        userService.addRoleByUser(roleToUserForm.getUserName(),roleToUserForm.getRoleName());
        return ResponseEntity.ok().build();
    }





//    @GetMapping("/user/getAll")
//    public List<User> getAllUser() {
//        return userService.getAllUser();
//    }

    @GetMapping("/user/getAll")
    public ResponseEntity<List<User>> getAllUser() {
        return  ResponseEntity.ok().body(userService.getAllUser());
    }

    @GetMapping("/user/get/{id}")
    public User getUserById(@PathVariable("id") Long id) {
        return userService.getUserById(id).get();
    }
}
