import crypto from 'crypto'
<%_ if (passwordSignup) { _%>
import bcrypt from 'bcrypt'
<%_ if (authServices.length) { _%>
import randtoken from 'rand-token'
<%_ } _%>
<%_ } _%>
import mongoose, { Schema, Model } from 'mongoose'
import mongooseKeywords from 'mongoose-keywords'
<%_ if (passwordSignup) { _%>
import config from '../../config'
<%_ } _%>

const roles = ['user', 'admin']

interface User extends mongoose.Document  {
  name: string;
  email: string;
  <%_ if (passwordSignup) { _%>
  password: string;
  <%_ } _%>
  <%_ if (authServices.length) { _%>
  services: { [key: string]: string; };
  <%_ } _%>
  role: string;
  picture: string;
  authenticate(password: string): Promise<Boolean>;
  [key:string]: any;
}

interface UserModel extends Model<User> {
  createFromService(user: any): Promise<any>;
  [key: string]: any;
}

const userSchema = new Schema({
  email: {
    type: String,
    match: /^\S+@\S+\.\S+$/,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  <%_ if (passwordSignup) { _%>
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  <%_ } _%>
  name: {
    type: String,
    index: true,
    trim: true
  },
  <%_ if (authServices.length) { _%>
  services: {
    <%_ authServices.forEach(function (service, i) { _%>
    <%= service %>: String<%- i !== authServices.length - 1 ? ',' : '' %>
    <%_ }) _%>
  },
  <%_ } _%>
  role: {
    type: String,
    enum: roles,
    default: 'user'
  },
  picture: {
    type: String,
    trim: true
  }
}, {
  timestamps: true
})

userSchema.path('email').set( (email: string) => {
  const that:any = this;
  if (!that.picture || that.picture.indexOf('https://gravatar.com') === 0) {
    const hash = crypto.createHash('md5').update(email).digest('hex')
    that.picture = `https://gravatar.com/avatar/${hash}?d=identicon`
  }

  if (!that.name) {
    that.name = email.replace(/^(.+)@.+$/, '$1')
  }

  return email
})

<%_ if (passwordSignup) { _%>
userSchema.pre('save', function (next) {
  if (!this.isModified('password')) return next()

  /* istanbul ignore next */
  const rounds = env === 'test' ? 1 : 9

  bcrypt.hash(this.password, rounds).then((hash) => {
    this.password = hash
    next()
  }).catch(next)
})

<%_ } _%>
userSchema.methods = {
  view (full) {
    const view: { [key: string]: any; } = {}
    let fields = ['id', 'name', 'picture']

    if (full) {
      fields = [...fields, 'email', 'createdAt']
    }

    fields.forEach((field) => { view[field] = this[field] })

    return view
  }<%_ if (passwordSignup) { _%>,

  authenticate (password) {
    return bcrypt.compare(password, this.password).then((valid) => valid ? this : false)
  }
  <%_ } _%>

}

userSchema.statics = {
  <%_ if (authServices.length) { _%>
  roles,

  createFromService ({ service, id, email, name, picture }) {
    return this.findOne({ $or: [{ [`services.${service}`]: id }, { email }] }).then((user) => {
      if (user) {
        user.services[service] = id
        user.name = name
        user.picture = picture
        return user.save()
      } else {
        <%_ if (passwordSignup) { _%>
        const password = randtoken.generate(16)
        <%_ } _%>
        return this.create({ services: { [service]: id }, email<% if (passwordSignup) { %>, password<% } %>, name, picture })
      }
    })
  }
  <%_ } else { _%>
  roles
  <%_ } _%>
}

userSchema.plugin(mongooseKeywords, { paths: ['email', 'name'] })

const model = mongoose.model('User', userSchema)

export const schema = model.schema
export default model
