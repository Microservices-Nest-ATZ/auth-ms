import { HttpStatus, Injectable } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { RegisterUserDto } from './dto/register-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt'
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService {

    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
    ) { }


    async registerUser(registerUserDto: RegisterUserDto) {
        const { name, email, password } = registerUserDto;

        try {
            const user = await this.prisma.user.findFirst({
                where: { email: email }
            });

            if (user) {
                throw new RpcException({
                    message: 'User already exists',
                    statusCode: HttpStatus.BAD_REQUEST,
                });
            }

            const newUser = await this.prisma.user.create({
                data: {
                    name: name,
                    email: email,
                    password: bcrypt.hashSync(password, 10),
                }
            });

            const { password: __, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJWT(rest),
            }
        } catch (error) {
            throw new RpcException({
                message: 'Error',
                statusCode: HttpStatus.BAD_REQUEST,
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto;

        try {

            const user = await this.prisma.user.findFirst({
                where: { email: email }
            });

            if (!user) {
                throw new RpcException({
                    message: 'User not exists',
                    statusCode: HttpStatus.BAD_REQUEST,
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    message: 'Password incorrect',
                    statusCode: HttpStatus.UNAUTHORIZED,
                });
            }

            const { password: __, ...rest } = user;

            return {
                user: rest,
                token: await this.signJWT(rest),
            }
        } catch (error) {
            throw new RpcException({
                message: 'Error',
                statusCode: HttpStatus.BAD_REQUEST,
            });
        }
    }

    async verifyToken(token: string) {
        try {
            const payload = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });

            const {sub, iat, exp, ...user} = payload;

            return {
                user: user,
                token: await this.signJWT(user),
            }
        } catch (error) {
            throw new RpcException({
                message: 'Token not valid',
                statusCode: HttpStatus.UNAUTHORIZED,
            });
        }
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

}
