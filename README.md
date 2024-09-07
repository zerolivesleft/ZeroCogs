# Zero's RedBot Cogs Repository

This repository contains custom cogs for Red-DiscordBot.

## Available Cogs

### TwitchScheduleSync

Synchronizes Twitch stream schedules with Discord events. This cog automatically fetches the Twitch schedule for a specified user and creates or updates corresponding Discord events.

## Installation

To add these cogs to your Red instance:

1. Add this repository:
   ```
   [p]repo add zeros-cogs https://github.com/yourusername/zeros-redbotcogs
   ```

2. Install the desired cog:
   ```
   [p]cog install zeros-cogs TwitchScheduleSync
   ```

3. Load the installed cog:
   ```
   [p]load TwitchScheduleSync
   ```

## TwitchScheduleSync Setup

1. Obtain Twitch API credentials:
   - Go to https://dev.twitch.tv/console/apps
   - Create a new application or use an existing one
   - Note down the Client ID and generate a new Client Secret

2. Set up the cog:
   ```
   [p]twitchset clientid <your_client_id>
   [p]twitchset clientsecret <your_client_secret>
   [p]twitchset username <twitch_username>
   ```

3. Verify settings:
   ```
   [p]show_twitch_settings
   ```

4. Force a sync:
   ```
   [p]force_sync
   ```

The cog will automatically sync every hour. Events in Discord will be created or updated to match the Twitch schedule, including stream title, category, start time, and thumbnail image.

Note: This cog requires the bot to have the 'Manage Events' permission in your Discord server.

## Support

If you encounter any issues or have questions, please open an issue in this repository.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).