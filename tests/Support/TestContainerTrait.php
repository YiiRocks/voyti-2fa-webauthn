<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support;

use Composer\InstalledVersions;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Yiisoft\Aliases\Aliases;
use Yiisoft\Cookies\CookieEncryptor;
use Yiisoft\Cookies\CookieSigner;
use Yiisoft\Csrf\CsrfTokenInterface;
use Yiisoft\Csrf\StubCsrfToken;
use Yiisoft\Di\Container;
use Yiisoft\Di\ContainerConfig;
use Yiisoft\Mailer\MailerInterface;
use Yiisoft\Router\CurrentRoute;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\Session\Flash\Flash;
use Yiisoft\Session\Flash\FlashInterface;
use Yiisoft\Session\SessionInterface;
use Yiisoft\Translator\CategorySource;
use Yiisoft\Translator\Message\Php\MessageSource;
use Yiisoft\Translator\SimpleMessageFormatter;
use Yiisoft\Translator\Translator;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\View\WebView;
use Yiisoft\Widget\WidgetFactory;
use Yiisoft\Yii\View\Renderer\InjectionContainer\InjectionContainer;
use Yiisoft\Yii\View\Renderer\InjectionContainer\InjectionContainerInterface;

/**
 * Builds a fresh PSR-11 DI container per test by merging the core module's `config/di.php`, the
 * voyti-2fa base package's, and this package's own, plus hydrator/validator, with in-memory fakes
 * overlaid. Per-test overrides are merged on top.
 */
trait TestContainerTrait
{
    /**
     * @param array<class-string|string, object|class-string|callable> $overrides
     */
    protected function createTestContainer(array $overrides = []): ContainerInterface
    {
        $corePath = InstalledVersions::getInstallPath('yiirocks/voyti');
        $twoFaPath = InstalledVersions::getInstallPath('yiirocks/voyti-2fa');
        $pkgPath = dirname(__DIR__, 2);

        $params = array_merge(
            require $corePath . '/config/params.php',
            require $twoFaPath . '/config/params.php',
            require $pkgPath . '/config/params.php',
        );

        $definitions = (static fn(array $params): array => require $corePath . '/config/di.php')($params);
        $definitions = array_merge(
            $definitions,
            (static fn(array $params): array => require $twoFaPath . '/config/di.php')($params),
            (static fn(array $params): array => require $pkgPath . '/config/di.php')($params),
        );

        $hydratorDiPath = InstalledVersions::getInstallPath('yiisoft/hydrator') . '/config/di.php';
        $definitions = array_merge(require $hydratorDiPath, $definitions);

        $validatorInstallPath = InstalledVersions::getInstallPath('yiisoft/validator');
        $validatorParams = require $validatorInstallPath . '/config/params.php';
        $validatorDiPath = $validatorInstallPath . '/config/di.php';
        $validatorDefinitions = (static fn(array $params): array => require $validatorDiPath)(
            array_merge($params, $validatorParams),
        );
        /** @var CategorySource $validatorCategorySource */
        $validatorCategorySource = $validatorDefinitions['yii.validator.categorySource']['definition']();
        $definitions = array_merge($validatorDefinitions, $definitions);

        $psr17Factory = new Psr17Factory();
        $session = new FakeSession();

        $definitions = array_merge($definitions, [
            Aliases::class => new Aliases(),
            CookieEncryptor::class => new CookieEncryptor('test-secret-key-0123456789abcdef'),
            CookieSigner::class => new CookieSigner('test-secret-key-0123456789abcdef'),
            CsrfTokenInterface::class => new StubCsrfToken('test-csrf-token'),
            CurrentRoute::class => new CurrentRoute(),
            EventDispatcherInterface::class => new EventCaptureDispatcher(),
            FlashInterface::class => new Flash($session),
            InjectionContainerInterface::class => InjectionContainer::class,
            LoggerInterface::class => new NullLogger(),
            MailerInterface::class => new MailCapture(),
            RequestFactoryInterface::class => $psr17Factory,
            ResponseFactoryInterface::class => $psr17Factory,
            SessionInterface::class => $session,
            StreamFactoryInterface::class => $psr17Factory,
            TranslatorInterface::class => (static function () use ($corePath, $twoFaPath, $pkgPath, $validatorCategorySource): TranslatorInterface {
                $translator = new Translator('en', null, 'voyti');
                $translator->addCategorySources(
                    new CategorySource('voyti', new MessageSource($corePath . '/resources/messages'), new SimpleMessageFormatter()),
                    new CategorySource('voyti-2fa', new MessageSource($twoFaPath . '/resources/messages'), new SimpleMessageFormatter()),
                    new CategorySource('voyti-2fa-webauthn', new MessageSource($pkgPath . '/resources/messages'), new SimpleMessageFormatter()),
                    $validatorCategorySource,
                );

                return $translator;
            })(),
            UrlGeneratorInterface::class => new FakeUrlGenerator(),
            WebView::class => new WebView(),
        ]);

        $definitions = array_merge($definitions, $overrides);

        $container = new Container(ContainerConfig::create()->withDefinitions($definitions));
        WidgetFactory::initialize($container);

        return $container;
    }
}
