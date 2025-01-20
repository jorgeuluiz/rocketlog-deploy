import { Request, Response, NextFunction } from "express"
import { verify } from "jsonwebtoken"

import { authConfig } from "@/configs/auth"
import { AppError } from "@/utils/AppError"

interface TokenPayload {
  role: string
  sub: string
}

function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction

) {
  try {
    const autHeader = request.headers.authorization

    if (!autHeader) {
      throw new AppError("JWT token not found", 401)
    }

    const [, token] = autHeader.split(" ")

    const { role, sub: user_id } = verify(token, authConfig.jwt.secret) as TokenPayload

    request.user = {
      id: user_id,
      role
    }

    return next()
    
  } catch (error) {
    throw new AppError("Invalid JWT token", 401)
  }
}

export { ensureAuthenticated }