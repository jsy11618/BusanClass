package securitySpringboot.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import securitySpringboot.user.dto.UserDto;
import securitySpringboot.user.model.Role;
import securitySpringboot.user.model.User;
import securitySpringboot.user.repository.RoleRepository;
import securitySpringboot.user.repository.UserRepository;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Transactional   // 동작하는 방식이 api가 아니라서 강제로 돌리는 것?
@Service
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository. findByUserName(username);
        if(user == null){
            log.error("User not found in the database.");
            throw new UsernameNotFoundException("User not found in the database.");
        }else{
            log.info("User found in the database. : {}", username);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassword(), authorities);
    }

    @Override
    public User addUser(User user) {
        log.info("Saving new User to the database. : {}", user.getUserName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
        // 우리는 공부 하는 중이기 때문에 예외처리(try~catch)는 제외하자
    }

    @Override
    public User addUserDto(UserDto userDto){
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        User user= User.builder()
                .id(null)
                .userName(userDto.getUserName())
                .userEmail(userDto.getUserEmail())
                .roles(new ArrayList<>())
                .password(userDto.getPassword())
                .build();
        return userRepository.save(user);
    }



    @Override
    public Role addRole(Role role) {
        log.info("Saving new Role to the database. : {}", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleByUser(String userName, String roleName) {
        log.info("Adding Role {} to User {} to the database.", roleName, userName);
        User user = userRepository.findByUserName(userName);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);   // 이 인터페이스의 조건은 유저와 롤이 이미 생성되 있어야 한다. 이미 생성 된 유저에 이미 생성된 롤을 등록
    }

    @Override
    public List<User> getAllUser() {
        log.info("Fetching All Users.");
        return userRepository.findAll();
    }

    @Override
    public User getUserByUserName(String userName) {
        log.info("Fetching User {}.", userName);
        return userRepository.findByUserName(userName);
    }

    @Override
    public Optional<User> getUserById(Long id) {
        log.info("get User by Id {}.", id);
        return Optional.ofNullable(userRepository.findById(id).get());
    }
}
