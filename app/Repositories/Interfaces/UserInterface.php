<?php

namespace App\Repositories\Interfaces;

/**
 * Class UserInterface
 * @package namespace App\Repositories\Interfaces;
 */
interface UserInterface
{
    /**
     * Find a user by id
     */
    public function findById($id): array;

    /**
     * Find a user by Id and Type
     */
    public function findByIdAndType($id, $type): array;

    /**
     * Increase the user balance
     */
    public function increaseBalanceById($value, $id): bool;

    /**
     * Decrease the user balance
     */
    public function decreaseBalanceById($value, $id): bool;
}
