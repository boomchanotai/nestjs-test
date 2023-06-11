import { ForbiddenException, Injectable, Request } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';

import { JwtService } from '@nestjs/jwt';

import * as argon2 from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup({ email, password }: AuthDto) {
    const hash = await argon2.hash(password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: email,
          password: hash,
        },
      });

      delete user.password;
      return user;
    } catch (error) {
      throw new ForbiddenException('Email already exists');
    }
  }

  async signin({ email, password }: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (user === null)
      throw new ForbiddenException('Email or password is incorrect');

    const isPasswordValid = await argon2.verify(user.password, password);
    if (!isPasswordValid)
      throw new ForbiddenException('Email or password is incorrect');

    const payload = { sub: user.id, email: user.email };
    delete user.password;
    return { access_token: await this.jwtService.signAsync(payload), ...user };
  }

  async getProfile({ email }: { email: string }) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    delete user.password;
    return user;
  }
}
