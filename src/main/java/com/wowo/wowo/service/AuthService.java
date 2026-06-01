package com.wowo.wowo.service;

import com.wowo.wowo.data.dto.CreateUserDTO;
import com.wowo.wowo.data.mapper.UserMapper;
import com.wowo.wowo.exception.BadRequest;
import com.wowo.wowo.model.Role;
import com.wowo.wowo.model.User;
import com.wowo.wowo.model.UserWallet;
import com.wowo.wowo.repository.RoleRepository;
import com.wowo.wowo.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserMapper userMapperImpl;

    public User register(CreateUserDTO dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new BadRequest("Email đã tồn tại");
        }
        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            throw new BadRequest("Tên đăng nhập đã tồn tại");
        }

        User user = new User();
        userMapperImpl.partialUpdateFromCreateDTO(dto, user);
        user.setId(UUID.randomUUID().toString().replace("-", ""));
        user.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        user.setIsActive(true);
        user.setIsVerified(true);

        Role userRole = roleRepository.findById(3)
                .orElseThrow(() -> new BadRequest("Role 'User' not found"));
        user.setRole(userRole);

        // Create user wallet
        UserWallet wallet = new UserWallet();
        user.setWallet(wallet);
        wallet.setUser(user);

        return userRepository.save(user);
    }

    public User login(String emailOrUsername, String password) {
        User user = userRepository.findFirstByIdOrEmailOrUsername("", emailOrUsername, emailOrUsername)
                .orElseThrow(() -> new BadRequest("Tài khoản hoặc mật khẩu không chính xác"));

        if (user.getPassword() == null || !bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new BadRequest("Tài khoản hoặc mật khẩu không chính xác");
        }

        return user;
    }
}
