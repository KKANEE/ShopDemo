package com.imooc.controller;

import com.imooc.pojo.Users;
import com.imooc.pojo.bo.UserBO;
import com.imooc.service.StuService;
import com.imooc.service.UserService;
import com.imooc.utils.CookieUtils;
import com.imooc.utils.IMOOCJSONResult;
import com.imooc.utils.JsonUtils;
import com.imooc.utils.MD5Utils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.rmi.server.ExportException;

@Api(value = "注册登录",tags = {"用于注册登录的相关接口"})
@RestController
@RequestMapping("passport")
public class PassportController {

    @Autowired
    private UserService userService;

    @ApiOperation(value="用户名是否存在",notes = "用户名是否存在",httpMethod = "GET")
    @GetMapping("/usernameIsExist")
    public IMOOCJSONResult usernameIsExit(@RequestParam(value = "username") String username){
        //1、使用apache的string工具类判断用户不能为空
        if(StringUtils.isBlank(username)){
            return IMOOCJSONResult.errorMsg("用户名不能为空");
        }
        //2.查找注册的用户名是否存在
        boolean isExist = userService.queryUsernameIsExist(username);
        if(isExist){
            return IMOOCJSONResult.errorMsg("用户名不能为空");
        }else {
            //3.请求成功，用户名没有重复
            return IMOOCJSONResult.ok();
        }
    }

    @ApiOperation(value="用户名注册",notes = "用户名注册",httpMethod = "POST")
    @PostMapping("/regist")
    public IMOOCJSONResult regist(@RequestBody UserBO userBO,
                                  HttpServletRequest request,
                                  HttpServletResponse response){
        String username = userBO.getUsername();
        String password = userBO.getPassword();
        String confirmPassword = userBO.getConfirmPassword();
        //1.判断用户名和密码是否为空
        if(StringUtils.isBlank(username)||
                StringUtils.isBlank(confirmPassword)||
                StringUtils.isBlank(password)){
            return IMOOCJSONResult.errorMsg("用户名和密码不能为空");
        }
        //2.查询用户是否存在
        boolean isExist = userService.queryUsernameIsExist(username);
        if(isExist){
            return IMOOCJSONResult.errorMsg("用户名已存在");
        }
        //3.密码长度不少于6位
        if(password.length()<6){
            return IMOOCJSONResult.errorMsg("密码长度不能少于6");
        }
        //4.判断两次密码是否一致
        if(!password.equals(confirmPassword)){
            return IMOOCJSONResult.errorMsg("密码不一致");
        }
        //5.实现注册
        Users user = userService.createUser(userBO);
        user = setNullProperty(user);
        CookieUtils.setCookie(request,response,"user",
                JsonUtils.objectToJson(user),true);
        return IMOOCJSONResult.ok();
    }

    @ApiOperation(value="用户登录",notes = "用户登录",httpMethod = "POST")
    @PostMapping("/login")
    public IMOOCJSONResult login(@RequestBody UserBO userBO,
                                 HttpServletRequest request,
                                 HttpServletResponse response) throws Exception {
        String username = userBO.getUsername();
        String password = userBO.getPassword();
        //1.判断用户名和密码是否为空
        if(StringUtils.isBlank(username)||
                StringUtils.isBlank(password)){
            return IMOOCJSONResult.errorMsg("用户名和密码不能为空");
        }

        //登录
        Users user = userService.queryUserForLogin(username,
                MD5Utils.getMD5Str(password));
        if(user == null){
            return IMOOCJSONResult.errorMsg("用户名或密码错误");
        }
        user = setNullProperty(user);
        CookieUtils.setCookie(request,response,"user",
                JsonUtils.objectToJson(user),true);
        return IMOOCJSONResult.ok(user);
    }

    private Users setNullProperty(Users user){
        user.setPassword(null);
        user.setMobile(null);
        user.setEmail(null);
        user.setCreatedTime(null);
        user.setUpdatedTime(null);
        user.setBirthday(null);
        return user;
    }
    @ApiOperation(value="用户退出",notes = "用户退出",httpMethod = "POST")
    @PostMapping("/logout")
    public IMOOCJSONResult logout(@RequestParam(value = "userId")String userId,
                                  HttpServletRequest request,
                                  HttpServletResponse response){
        //清除用户相关信息cookie
        CookieUtils.deleteCookie(request,response,"user");
        //TODO 用户退出登录，需要清空购物车
        //TODO 分布式会话中需要清除用户数据
        return IMOOCJSONResult.ok();
    }
}
