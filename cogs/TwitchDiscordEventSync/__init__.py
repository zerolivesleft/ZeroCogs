from .twitch_schedule_sync import TwitchScheduleSync

async def setup(bot):
    await bot.add_cog(TwitchScheduleSync(bot))