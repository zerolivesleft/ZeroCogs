from redbot.core import commands, Config
import discord
from discord.ext import tasks
import aiohttp
import os
from datetime import datetime, timedelta

class TwitchScheduleSync(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=5599887514)  # Use a unique identifier
        default_global = {
            "twitch_client_id": None,
            "twitch_client_secret": None,
            "twitch_username": None
        }
        self.config.register_global(**default_global)
        self.twitch_client_id = self.config.get_global("twitch_client_id")
        self.twitch_client_secret = self.config.get_global("twitch_client_secret")
        self.twitch_username = self.config.get_global("twitch_username")
        self.sync_schedule.start()

    def cog_unload(self):
        self.sync_schedule.cancel()

    @tasks.loop(hours=24)
    async def sync_schedule(self):
        await self._do_sync()

    async def _do_sync(self):
        # Fetch Twitch access token
        access_token = await self.get_twitch_access_token()
        if not access_token:
            raise Exception("Failed to get Twitch access token")

        # Fetch Twitch schedule
        schedule = await self.fetch_twitch_schedule(access_token)
        if not schedule:
            raise Exception("Failed to fetch Twitch schedule")

        # Sync with Discord events
        await self.sync_discord_events(schedule)

    async def get_twitch_access_token(self):
        url = "https://id.twitch.tv/oauth2/token"
        client_id = await self.config.twitch_client_id()
        client_secret = await self.config.twitch_client_secret()
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data["access_token"]
        return None

    async def fetch_twitch_schedule(self, access_token):
        username = await self.config.twitch_username()
        client_id = await self.config.twitch_client_id()
        url = f"https://api.twitch.tv/helix/schedule?broadcaster_id={username}"
        headers = {
            "Client-ID": client_id,
            "Authorization": f"Bearer {access_token}"
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
        return None

    async def sync_discord_events(self, schedule):
        guild = self.bot.guilds[0]  # Assuming the bot is in only one guild
        for segment in schedule["data"]["segments"]:
            start_time = datetime.fromisoformat(segment["start_time"])
            end_time = start_time + timedelta(hours=2)  # Assuming 2-hour events
            event_name = f"Twitch Stream: {segment['title']}"

            # Check if event already exists
            existing_event = discord.utils.get(await guild.fetch_scheduled_events(), name=event_name)
            if existing_event:
                await existing_event.edit(
                    name=event_name,
                    description=segment["category"]["name"],
                    start_time=start_time,
                    end_time=end_time
                )
            else:
                await guild.create_scheduled_event(
                    name=event_name,
                    description=segment["category"]["name"],
                    start_time=start_time,
                    end_time=end_time,
                    entity_type=discord.EntityType.external,
                    location=f"https://twitch.tv/{self.twitch_username}"
                )

    @sync_schedule.before_loop
    async def before_sync_schedule(self):
        await self.bot.wait_until_ready()

    @commands.command()
    async def force_sync(self, ctx):
        """Force a sync of the Twitch schedule to Discord events"""
        await self.sync_schedule()
        await ctx.send("Twitch schedule sync completed.")

async def setup(bot):
    await bot.add_cog(TwitchScheduleSync(bot))
    @twitchsync.command()
    @commands.is_owner()
    async def forcesync(self, ctx):
        """Force a sync of the Twitch schedule to Discord events"""
        await ctx.send("Starting Twitch schedule sync...")
        try:
            await self.sync_schedule()
            await ctx.send("Twitch schedule sync completed successfully.")
        except Exception as e:
            await ctx.send(f"An error occurred during sync: {str(e)}")