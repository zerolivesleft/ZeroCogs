from .PlaylistCreator import URLGrabber

async def setup(bot):
    await bot.add_cog(URLGrabber(bot))