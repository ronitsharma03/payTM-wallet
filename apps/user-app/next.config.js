/** @type {import('next').NextConfig} */
module.exports = {
  transpilePackages: ["@repo/ui"],
  typescript: {
    ignoreBuildErrors: true
  }
};
