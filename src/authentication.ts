import security from '@architecturex/utils.security'
import is from '@architecturex/utils.is'
import jwt from 'jsonwebtoken'

export const secretKey = 'Tru3C4b1n5'
export const expiresIn = '30d'

export const createToken = async (user: any): Promise<string[] | string> => {
  const {
    id,
    user_role_id,
    tier_id,
    tier,
    personal_information,
    username,
    password,
    email,
    active,
    role,
    theme,
    language
  } = user
  const token = security.base64.encode(`${security.password.encrypt(secretKey)}${password}`)
  const userData = {
    id,
    user_role_id,
    tier_id,
    tier,
    role,
    personal_information,
    username,
    email,
    active,
    token,
    theme,
    language
  }

  const createTk = jwt.sign({ data: security.base64.encode(userData) }, secretKey, {
    expiresIn
  })

  return Promise.all([createTk])
}

export const getUserBy = async (where: any, roles: string[], models: any): Promise<any> => {
  const user = await models.User.findOne({
    where,
    raw: true
  })

  if (user && roles.includes(user.role)) {
    return user
  }

  return null
}

export const authenticate = async (
  emailOrUsername: string,
  password: string,
  models: any
): Promise<any> => {
  const where = is(emailOrUsername).email()
    ? { email: emailOrUsername }
    : { username: emailOrUsername }

  const user = await getUserBy(
    where,
    ['global::god', 'global::admin', 'business::admin', 'business::editor', 'business::agent'],
    models
  )

  if (!user) {
    throw new Error('Invalid Login')
  }

  const passwordMatch = security.password.match(security.password.encrypt(password), user.password)
  const isActive = user.active

  if (!passwordMatch) {
    throw new Error('Invalid Login')
  }

  if (!isActive) {
    throw new Error('Your account is not activated yet')
  }

  const [token] = await createToken(user)

  return {
    token
  }
}

export function jwtVerify(accessToken: string, cb: any): any {
  jwt.verify(accessToken, secretKey, (error: any, accessTokenData: any = {}) => {
    const { data: user } = accessTokenData

    if (error || !user) {
      return cb(false)
    }

    const userData = security.base64.decode(user)

    return cb(userData)
  })

  return null
}

export async function getUserData(accessToken: any): Promise<any> {
  const UserPromise = new Promise((resolve) => jwtVerify(accessToken, (user: any) => resolve(user)))

  const user = await UserPromise

  return user
}
