import {
  ConfigArgs,
  getWebpackCommonConfig,
  getWebpackDevelopmentConfig,
  getWebpackProductionConfig,
  log
} from '@architecturex/devtools'

import { Configuration } from 'webpack'
import { merge } from 'webpack-merge'

import { name } from './package.json'

// Package Name
const [, packageName] = name.split('/')

// Mode Config
const getModeConfig = {
  development: getWebpackDevelopmentConfig,
  production: getWebpackProductionConfig
}

// Mode Configuration (development/production)
const modeConfig: (args: ConfigArgs) => Configuration = ({ mode }) => {
  const getWebpackConfiguration = getModeConfig[mode]

  return getWebpackConfiguration()
}

// Merging all configurations
const webpackConfig: (args: ConfigArgs) => Promise<Configuration> = async (
  { mode } = {
    mode: 'production'
  }
) => {
  const commonConfiguration = getWebpackCommonConfig({
    packageName,
    mode,
    isMonoRepo: false
  })

  // Mode Configuration
  const modeConfiguration = mode ? modeConfig({ mode }) : {}

  // Merging all configurations
  const webpackConfiguration = merge(commonConfiguration, modeConfiguration)

  // Logging Webpack Configuration
  log({ tag: 'Webpack Configuration', json: webpackConfiguration, type: 'warning' })

  return webpackConfiguration
}

export default webpackConfig
